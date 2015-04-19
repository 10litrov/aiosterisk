import asyncio
import logging
import re
from hashlib import md5

from .common import AMICommandFailure, ami_action

log = logging.getLogger(__package__)


class AMIProtocol(asyncio.Protocol):
    """Asterisk AMI protocol implementation"""
    def __init__(self, loop=None):
        self._action_futures = {}
        self._event_handlers = {}
        self._tasks = []

        self._hostname = None
        self._count = 0

        self.transport = None
        self.loop = loop or asyncio.get_event_loop()

        self._message_queue = asyncio.Queue(loop=self.loop)
        self._tasks.append(asyncio.async(self._dispatch_message(), loop=self.loop))

    def connection_made(self, transport):
        log.info('Connection made to {0}:{1:d}'.format(*transport.get_extra_info('peername')))
        self.transport = transport
        self._hostname = '{0}:{1:d}'.format(*transport.get_extra_info('sockname'))

    def connection_lost(self, exc):
        if exc is not None:
            log.warn('Connection lost: {}'.format(exc))

    def data_received(self, data):
        self._message_queue.put_nowait(data.decode())

    def close(self):
        for task in self._tasks:
            task.cancel()
        for future in self._action_futures.values():
            future.cancel()
        self.transport.close()

    def _dispatch_message(self):
        message = {}
        try:
            while True:
                # wait for next line
                line = yield from self._message_queue.get()
                for tag in line.splitlines():
                    if tag:
                        matches = re.match('^(\S+):\s*(.+)?$', tag)
                        if matches:  # it's a tag: value
                            message.update((matches.groups(),))
                        else:  # it's a command output or other plain text
                            message.setdefault('_', []).append(tag)
                    else:  # message ends
                        if message:
                            if 'ActionID' in message:
                                log.debug('Incoming message: {!r}'.format(message))
                                future = self._action_futures.get(message['ActionID'])
                                if future:
                                    if message.get('Response') == 'Error':
                                        future.set_exception(AMICommandFailure(message.get('Message')))
                                    else:
                                        future.set_result(message)
                                    # del self.action_futures[message['ActionID']]
                            if 'Event' in message:
                                log.debug('Incoming event: {!r}'.format(message))
                                for event in self._event_handlers.get(message['Event'], []):
                                    self.loop.call_soon(event, message)
                            message = {}  # prepare for the next message
        except asyncio.CancelledError:
            pass

    def _generateActionId(self):
        self._count += 1
        return '{0}-{1}-{2:d}'.format(self._hostname, id(self), self._count)

    def sendMessage(self, message):
        """Sends a message to asterisk through AMI

        :param message: the message (multiple tag: value) to send
        :type message: list or tuple or dict
        :return: asyncio.Future
        """
        if type(message) == dict:
            data = message.items()
        else:
            data = message

        future = asyncio.Future(loop=self.loop)
        actionid = self._generateActionId()
        self._action_futures[actionid] = future

        self.transport.write('ActionID: {:s}\n'.format(actionid).encode())
        for key, value in filter(lambda item: item[0].lower() != 'actionid', data):
            self.transport.write('{0:s}: {1:s}\n'.format(key.lower(), value).encode())
        self.transport.write('\n'.encode())

        return future

    def on(self, event, callback):
        self._event_handlers.setdefault(event, []).append(callback)
        return self

    def off(self, event, callback):
        events = self._event_handlers.get(event, [])
        for i in [index for index, value in enumerate(events) if value == callback]:
            events.pop(i)
        return self

    @ami_action
    def absoluteTimeout(self, channel, timeout):
        """Set absolute timeout.

        Hangup a channel after a certain time. Acknowledges set time with Timeout Set message.

        :param channel: Channel name to hangup
        :param timeout: Maximum duration of the call (sec)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'AbsoluteTimeout',
            'Timeout': timeout,
            'Channel': channel
        })

    @ami_action
    def agentLogoff(self, agent, soft):
        """Sets an agent as no longer logged in.

        :param agent: Agent ID of the agent to log off
        :param soft: Set to true to not hangup existing calls
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'AgentLogoff',
            'Agent': agent,
            'Soft': 'true' if soft in (True, 'yes', 1) else 'false'
        })

    @ami_action
    def agents(self):
        """Lists agents and their status.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Agents'
        })

    @ami_action
    def agi(self, channel, command, command_id):
        """Add an AGI command to execute by Async AGI.

        Add an AGI command to the execute queue of the channel in Async AGI.

        :param channel: Channel that is currently in Async AGI
        :param command: Application to execute
        :param command_id: This will be sent back in CommandID header of AsyncAGI exec event notification
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'AGI',
            'Channel': channel,
            'Command': command,
            'CommandID': command_id
        })

    @ami_action
    def atxfer(self, channel, exten, context, priority):
        """Attended transfer.

        :param channel: Transferer's channel
        :param exten: Extension to transfer to
        :param context: Context to transfer to
        :param priority: Priority to transfer to
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Atxfer',
            'Channel': channel,
            'Exten': exten,
            'Context': context,
            'Priority': priority
        })

    @ami_action
    def bridge(self, channel1, channel2, tone):
        """Bridge two channels already in the PBX.

        :param channel1: Channel to Bridge to Channel2
        :param: channel2: Channel to Bridge to Channel1
        :param: tone: Play courtesy tone to Channel 2 (yes or no)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Bridge',
            'Channel1': channel1,
            'Channel2': channel2,
            'Tone': 'yes' if tone in (True, 'yes', 1) else 'no'
        })

    @ami_action
    def changeMonitor(self, channel, filename):
        """Change monitoring filename of a channel.

        This action may be used to change the file started by a previous 'Monitor' action.

        :param channel: Used to specify the channel to record
        :param filename: The new name of the file created in the monitor spool directory
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ChangeMonitor',
            'Channel': channel,
            'File': filename
        })

    @ami_action
    def command(self, command):
        """Execute Asterisk CLI Command.

        :param command: Asterisk CLI command to run
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Command',
            'Command': command
        })

    @ami_action
    def coreSettings(self):
        """Show PBX core settings (version etc).

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'CoreSettings'
        })

    @ami_action
    def coreShowChannels(self):
        """List currently defined channels and some information about them.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'CoreShowChannels'
        })

    @ami_action
    def coreStatus(self):
        """Show PBX core status variables.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'CoreStatus'
        })

    @ami_action
    def createConfig(self, filename):
        """Creates an empty file in the configuration directory.

        This action will create an empty file in the configuration directory.
        This action is intended to be used before an UpdateConfig action.

        :param filename: The configuration filename to create (e.g. foo.conf)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'CreateConfig',
            'Filename': filename
        })

    @ami_action
    def dahdiDialOffhook(self, channel, number):
        """Dial over DAHDI channel while offhook.

        Generate DTMF control frames to the bridged peer.

        :param channel: DAHDI channel number to dial digits
        :param number: Digits to dial
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIDialOffhook',
            'DAHDIChannel': channel,
            'Number': number
        })

    @ami_action
    def dahdiDNDoff(self, channel):
        """Toggle DAHDI channel Do Not Disturb status OFF.

        Equivalent to the CLI command "dahdi set dnd channel off".
        Feature only supported by analog channels.

        :param channel: DAHDI channel number to set DND off
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIDNDoff',
            'DAHDIChannel': channel
        })

    @ami_action
    def dahdiDNDon(self, channel):
        """Toggle DAHDI channel Do Not Disturb status ON.

        Equivalent to the CLI command "dahdi set dnd channel on".
        Feature only supported by analog channels.

        :param channel: DAHDI channel number to set DND on
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIDNDon',
            'DAHDIChannel': channel
        })

    @ami_action
    def dahdiHangup(self, channel):
        """Hangup DAHDI Channel.

        Simulate an on-hook event by the user connected to the channel.
        Valid only for analog channels.

        :param channel: DAHDI channel number to hangup
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIHangup',
            'DAHDIChannel': channel
        })

    @ami_action
    def dahdiRestart(self):
        """Fully Restart DAHDI channels (terminates calls).

        Equivalent to the CLI command "dahdi restart".

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIRestart',
        })

    @ami_action
    def dahdiShowChannels(self, channel=0):
        """Show status of DAHDI channels.

        Similar to the CLI command "dahdi show channels".

        :param channel: Specify the specific channel number to show. Show all channels if zero or not present
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDIShowChannels',
            'DAHDIChannel': channel
        })

    @ami_action
    def dahdiTransfer(self, channel):
        """Transfer DAHDI Channel.

        Simulate a flash hook event by the user connected to the channel.
        Valid only for analog channels.

        :param channel: DAHDI channel number to transfer
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DAHDITransfer',
            'DAHDIChannel': channel
        })

    @ami_action
    def dataGet(self, path, search, filter):
        """Retrieve the data api tree.

        :param path:
        :param search:
        :param filter:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DataGet',
            'Path': path,
            'Search': search,
            'Filter': filter
        })

    @ami_action
    def dbDel(self, family, key):
        """Delete DB entry.

        :param family:
        :param key:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DBDel',
            'Family': family,
            'Key': key
        })

    @ami_action
    def dbDelTree(self, family, key=None):
        """Delete DB Tree.

        :param family:
        :param key:
        :return: asyncio.Future
        """
        message = {
            'Action': 'DBDelTree',
            'Family': family
        }
        if key is not None:
            message['key'] = key
        return self.sendMessage(message)

    @ami_action
    def dbGet(self, family, key):
        """Get DB Entry.

        :param family:
        :param key:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DBGet',
            'Family': family,
            'Key': key
        })

    @ami_action
    def dbPut(self, family, key, value):
        """Put DB entry.

        :param family:
        :param key:
        :param value:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'DBPut',
            'Family': family,
            'Key': key,
            'Val': value
        })

    @ami_action
    def events(self, eventmask=False):
        """Control Event Flow.

        Enable/Disable sending of events to this manager client.

        :param eventmask: on - If all events should be sent;
         off - If no events should be sent;
         system,call,log,... - To select which flags events should have to be sent
        :return: asyncio.Future
        """
        if eventmask in ('off', False, 0):
            eventmask = 'off'
        elif eventmask in ('on', True, 1):
            eventmask = 'on'
        return self.sendMessage({
            'Action': 'Events',
            'EventMask': eventmask
        })

    @ami_action
    def extensionState(self, exten, context):
        """Check Extension Status.

        Report the extension state for given extension.
        If the extension has a hint, will use devicestate to check the status of the device connected to the extension.
        Will return an Extension Status message. The response will include the hint for the extension and the status.

        :param exten: Extension to check state on
        :param context: Context for extension
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ExtensionState',
            'Exten': exten,
            'Context': context
        })

    @ami_action
    def getConfig(self, filename, category=None):
        """Retrieve configuration.

        This action will dump the contents of a configuration file by category
        or optionally by specified filename only.

        :param filename: Configuration filename (e.g. foo.conf)
        :param category:  Category in configuration file
        :return: asyncio.Future
        """
        message = {
            'Action': 'GetConfig',
            'Filename': filename
        }
        if category:
            message['Category'] = category
        return self.sendMessage(message)

    @ami_action
    def getConfigJson(self, filename):
        """Retrieve configuration (JSON format).

        This action will dump the contents of a configuration file by category and contents in JSON format.

        :param filename: Configuration filename (e.g. foo.conf)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'GetConfigJSON',
            'Filename': filename
        })

    @ami_action
    def getVar(self, variable, channel=None):
        """Gets a channel variable or function value.

        Get the value of a channel variable or function return.
        If a channel name is not provided then the variable is considered global.

        :param variable: Variable name, function or expression
        :param channel: Channel to read variable from
        :return: asyncio.Future
        """
        message = {
            'Action': 'GetVar',
            'Variable': variable
        }
        if channel:
            message['Channel'] = channel
        return self.sendMessage(message)

    @ami_action
    def hangup(self, channel, cause):
        """Hangup channel.

        :param channel: The channel name to be hangup
        :param cause: Numeric hangup cause
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Hangup',
            'Channel': channel,
            'Cause': cause
        })

    @ami_action
    def iaxNetStats(self):
        """Show IAX channels network statistics.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'IAXnetstats'
        })

    @ami_action
    def iaxPeerList(self):
        """List all the IAX peers.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'IAXpeerlist'
        })

    @ami_action
    def iaxPeers(self):
        """List IAX peers.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'IAXpeers'
        })

    @ami_action
    def iaxRegisrty(self):
        """Show IAX registrations.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'IAXregistry'
        })

    @ami_action
    def jabberSend(self, jabber, jid, message):
        """Sends a message to a Jabber Client.

        :param jabber: Client or transport Asterisk uses to connect to JABBER
        :param jid: XMPP/Jabber JID (Name) of recipient
        :param message: Message to be sent to the buddy
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'JabberSend',
            'Jabber': jabber,
            'JID': jid,
            'Message': message
        })

    @ami_action
    def listCategories(self, filename):
        """This action will dump the categories in a given file.

        :param filename: Configuration filename (e.g. foo.conf).
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ListCategories',
            'Filename': filename
        })

    @ami_action
    def listCommands(self):
        """List available manager commands.

        Returns the action name and synopsis for every action that is available to the user.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ListCommands'
        })

    @ami_action
    def localOptimizeAway(self, channel):
        """Optimize away a local channel when possible.

        A local channel created with "/n" will not automatically optimize away.
        Calling this command on the local channel will clear that flag
        and allow it to optimize away if it's bridged or when it becomes bridged.

        :param channel: The channel name to optimize away
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'LocalOptimizeAway',
            'Channel': channel
        })

    def login(self, username, secret, plaintext_login=False):
        """Login Manager."""

        def _loginPlainText():
            return self.sendMessage({
                'Action': 'Login',
                'Username': username,
                'Secret': secret
            })

        def _loginChallengeResponse():
            challenge = yield from self.sendMessage({
                'Action': 'Challenge',
                'AuthType': 'MD5'
            })
            key = md5('{0}{1}'.format(challenge['Challenge'], secret).encode()).hexdigest()
            return self.sendMessage({
                'Action': 'Login',
                'AuthType': 'MD5',
                'Username': username,
                'Key': key
            })

        try:
            if plaintext_login:
                yield from _loginPlainText()
            else:
                yield from _loginChallengeResponse()
        except AMICommandFailure as e:
            log.error('Authentication {0}@{1[0]} failed'.format(username, self.transport.get_extra_info('peername')))
            raise e
        else:
            log.info('Authentication {0}@{1[0]} succeded'.format(username, self.transport.get_extra_info('peername')))

    def logoff(self):
        """Logoff the current manager session."""
        return self.sendMessage({
            'Action': 'Logoff'
        })

    @ami_action
    def mailboxCount(self, mailbox):
        """Check Mailbox Message Count.

        Checks a voicemail account for new messages.
        Returns number of urgent, new and old messages.

        :param mailbox: Full mailbox ID mailbox@vm-context
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'MailboxCount',
            'Mailbox': mailbox
        })

    @ami_action
    def mailboxStatus(self, mailbox):
        """Check mailbox.

        Checks a voicemail account for status.
        Returns whether there are messages waiting.

        :param mailbox: Full mailbox ID mailbox@vm-context
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'MailboxStatus',
            'Mailbox': mailbox
        })

    @ami_action
    def meetmeList(self, conference=None):
        """List participants in a conference.

        Lists all users in a particular MeetMe conference.
        MeetmeList will follow as separate events, followed by a final event called MeetmeListComplete.

        :param conference: Conference number
        :return: asyncio.Future
        """
        message = {
            'Action': 'MeetmeList'
        }
        if conference:
            message['Conference'] = conference
        return self.sendMessage(message)

    @ami_action
    def meetmeMute(self, meetme, usernum):
        """Mute a Meetme user.

        :param meetme:
        :param usernum:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'MeetmeMute',
            'Meetme': meetme,
            'Usernum': usernum
        })

    @ami_action
    def meetmeUnmute(self, meetme, usernum):
        """Unmute a Meetme user.

        :param meetme:
        :param usernum:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'MeetmeUnmute',
            'Meetme': meetme,
            'Usernum': usernum
        })

    @ami_action
    def mixMonitorMute(self, channel, direction, state):
        """Mute / unMute a Mixmonitor recording.

        :param channel: Used to specify the channel to mute
        :param direction: Which part of the recording to mute:
                          read, write or both (from channel, to channel or both channels)
        :param state: Turn mute on or off : 1 to turn on, 0 to turn off
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'MixMonitorMute',
            'Channel': channel,
            'Direction': direction,
            'State': state
        })

    @ami_action
    def moduleCheck(self, module):
        """Check if module is loaded.

        Checks if Asterisk module is loaded.
        Will return Success/Failure. For success returns, the module revision number is included.

        :param module: Asterisk module name (not including extension)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ModuleCheck',
            'Module': module
        })

    @ami_action
    def moduleLoad(self, module, loadtype):
        """Loads, unloads or reloads an Asterisk module in a running system.

        :param module: Asterisk module name (including .so extension) or subsystem identifier:
                       cdr, dnsmgr, extconfig, enum, manager, http, logger, features, dsp, udptl, indications, cel, plc
        :param loadtype: The operation to be done on module. Subsystem identifiers may only be reloaded
         load, unload, reload. If no module is specified for a reload loadtype, all modules are reloaded
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ModuleLoad',
            'Module': module,
            'LoadType': loadtype
        })

    @ami_action
    def monitor(self, channel, file, format, mix):
        """This action may be used to record the audio on a specified channel.

        :param channel: Used to specify the channel to record
        :param file: The name of the file created in the monitor spool directory.
         Defaults to the same name as the channel (with slashes replaced with dashes)
        :param format: the audio recording format
        :param mix: Boolean parameter as to whether to mix the input and output channels together
                    after the recording is finished
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Monitor',
            'Channel': channel,
            'File': file,
            'Format': format,
            'Mix': mix
        })

    @ami_action
    def originate(self, channel, context=None, exten=None, priority=None, timeout=None, callerid=None,
                  account=None, application=None, data=None, variables=None, async=False, codecs=None):
        """Originate a call.

        Generates an outgoing call to a Extension/Context/Priority or Application/Data

        :param channel: Channel name to call
        :param context: Context to use (requires Exten and Priority)
        :param exten: Extension to use (requires Context and Priority)
        :param priority: Priority to use (requires Exten and Context)
        :param timeout: How long to wait for call to be answered (in seconds)
        :param callerid: Caller ID to be set on the outgoing channel
        :param account: Account code
        :param application: Application to execute
        :param data: Data to use (requires Application)
        :param variables: Channel variable to set, multiple Variable: headers are allowed
        :param async: Set to true for fast origination
        :param codecs: Comma-separated list of codecs to use for this call
        :return: asyncio.Future
        """
        if not variables:
            variables = {}
        message = [(k, v) for k, v in (
            ('Action', 'Originate'),
            ('Channel', channel),
            ('Context', context),
            ('Exten', exten),
            ('Priority', priority),
            ('Callerid', callerid),
            ('Account', account),
            ('Application', application),
            ('Data', data),
            ('Codec', codecs),
            ('Async', str(async))) if v is not None]
        if timeout is not None:
            message['Timeout'] = timeout * 1000
        for variable in variables.items():
            message.append(('Variable', '{0:s}={1:s}'.format(*variable)))
        return self.sendMessage(message)

    @ami_action
    def park(self, channel, channel2, timeout, parkinglot):
        """Park a channel.

        :param channel: Channel name to park
        :param channel2: Channel to return to if timeout
        :param timeout: Number of milliseconds to wait before callback
        :param parkinglot: Specify in which parking lot to park the channel
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Park',
            'Channel': channel,
            'Channel2': channel2,
            'Timeout': timeout,
            'Parkinglot': parkinglot
        })

    @ami_action
    def parkedCalls(self):
        """List parked calls.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'ParkedCalls'
        })

    @ami_action
    def pauseMonitor(self, channel):
        """Pause monitoring of a channel.

        This action may be used to temporarily stop the recording of a channel.

        :param channel: Used to specify the channel to record
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'PauseMonitor',
            'Channel': channel
        })

    @ami_action
    def ping(self):
        """Keepalive command.

        A 'Ping' action will elicit a 'Pong' response. Used to keep the manager connection open.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Ping'
        })

    @ami_action
    def playDTMF(self, channel, digit):
        """Play DTMF signal on a specific channel.

        :param channel: Channel name to send digit to
        :param digit: The DTMF digit to play
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'PlayDTMF',
            'Channel': channel,
            'Digit': digit
        })

    @ami_action
    def queueAdd(self, queue, interface, penalty=0, paused=True,
                 membername=None, stateinterface=None):
        """Add interface to queue.

        :param queue: Queue's name
        :param interface: The name of the interface (tech/name) to add to the queue
        :param penalty: A penalty (number) to apply to this member.
                        Asterisk will distribute calls to members with higher penalties
                        only after attempting to distribute calls to those with lower penalty
        :param paused: To pause or not the member initially (true/false or 1/0)
        :param membername: Text alias for the interface
        :param stateinterface:
        :return: asyncio.Future
        """
        message = {
            'Action': 'QueueAdd',
            'Queue': queue,
            'Interface': interface,
            'Penalty': penalty,
            'Paused': 'true' if paused in (True, 'true', 1) else 'false'
        }
        if membername is not None:
            message['MemberName'] = membername
        if stateinterface is not None:
            message['StateInterface'] = stateinterface
        return self.sendMessage(message)

    @ami_action
    def queueLog(self, queue, event, uniqueid=None, interface=None, msg=None):
        """Adds custom entry in queue_log.

        :param queue:
        :param event:
        :param uniqueid:
        :param interface:
        :param msg:
        :return: asyncio.Future
        """
        message = {
            'Action': 'QueueLog',
            'Queue': queue,
            'Event': event
        }
        if uniqueid is not None:
            message['Uniqueid'] = uniqueid
        if interface is not None:
            message['Interface'] = interface
        if msg is not None:
            message['Message'] = msg
        return self.sendMessage(message)

    @ami_action
    def queuePause(self, queue, interface, paused=True, reason=None):
        """Pause or unpause a member in a queue.

        :param queue: The name of the queue in which to pause or unpause this member.
                      If not specified, the member will be paused or unpaused in all the queues it is a member of
        :param interface: The name of the interface (tech/name) to pause or unpause
        :param paused: Pause or unpause the interface. Set to 'true' to pause the member or 'false' to unpause
        :param reason: Text description, returned in the event QueueMemberPaused
        :return: asyncio.Future
        """
        message = {
            'Action': 'QueuePause',
            'Queue': queue,
            'Interface': interface,
            'Paused': 'true' if paused in (True, 'true', 1) else 'false'
        }
        if reason is not None:
            message['Reason'] = reason
        return self.sendMessage(message)

    @ami_action
    def queuePenalty(self, interface, penalty, queue=None):
        """Set the penalty for a queue member.

        :param interface: The interface (tech/name) of the member whose penalty to change
        :param penalty: The new penalty (number) for the member. Must be nonnegative
        :param queue: If specified, only set the penalty for the member of this queue.
                      Otherwise, set the penalty for the member in all queues to which the member belongs
        :return: asyncio.Future
        """
        message = {
            'Action': 'QueuePenalty',
            'Interface': interface,
            'Penalty': penalty
        }
        if queue is not None:
            message['Queue'] = queue
        return self.sendMessage(message)

    @ami_action
    def queueReload(self, queue, members=False, rules=False, parameters=False):
        """Reload a queue, queues, or any sub-section of a queue or queues.

        :param queue: The name of the queue to take action on.
                      If no queue name is specified, then all queues are affected
        :param members: Whether to reload the queue's members (yes or no)
        :param rules: Whether to reload queuerules.conf (yes or no)
        :param parameters: Whether to reload the other queue options (yes or no)
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'QueueReload',
            'Queue': queue,
            'Members': 'yes' if members in (True, 'yes', 1) else 'no',
            'Rules': 'yes' if rules in (True, 'yes', 1) else 'no',
            'Parameters': 'yes' if parameters in (True, 'yes', 1) else 'no'
        })

    @ami_action
    def queueRemove(self, queue, interface):
        """Remove interface from queue.

        :param queue: The name of the queue to take action on
        :param interface: The interface (tech/name) to remove from queue
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'QueueRemove',
            'Queue': queue,
            'Interface': interface
        })

    @ami_action
    def queueReset(self, queue):
        """Reset queue statistics.

        :param queue: The name of the queue on which to reset statistics
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'QueueReset',
            'Queue': queue
        })

    @ami_action
    def queueRule(self, rule):
        """List queue rules defined in queuerules.conf

        :param rule: The name of the rule in queuerules.conf whose contents to list
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'QueueRule',
            'Rueue': rule
        })

    @ami_action
    def queues(self):
        """Show queues information.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Queues'
        })

    @ami_action
    def queueStatus(self, queue=None, member=None):
        """Check the status of one or more queues.

        :param queue: Limit the response to the status of the specified queue
        :param member: Limit the response to the status of the specified member
        :return: asyncio.Future
        """
        message = {
            'Action': 'QueueStatus'
        }
        if queue is not None:
            message['Queue'] = queue
        if member is not None:
            message['Member'] = member
        return self.sendMessage(message)

    @ami_action
    def queueSummary(self, queue):
        """Show queue summary.

        Request the manager to send a QueueSummary event.

        :param queue: Queue for which the summary is requested
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'QueueSummary',
            'Queue': queue
        })

    @ami_action
    def redirect(self, channel, context, exten, priority,
                 extra_channel=None, extra_exten=None, extra_context=None, extra_priority=None):
        """Redirect (transfer) a call.

        :param channel: Channel to redirect
        :param context: Context to transfer to
        :param exten: Extension to transfer to
        :param priority: Priority to transfer to
        :param extra_channel: Second call leg to transfer (optional)
        :param extra_exten: Extension to transfer extrachannel to (optional)
        :param extra_context: Context to transfer extrachannel to (optional)
        :param extra_priority: Priority to transfer extrachannel to (optional)
        :return: asyncio.Future
        """
        message = {
            'Action': 'Redirect',
            'Channel': channel,
            'Context': context,
            'Exten': exten,
            'Priority': priority,
        }
        if extra_channel is not None:
            message['ExtraChannel'] = extra_channel
        if extra_channel is not None:
            message['ExtraExten'] = extra_exten
        if extra_channel is not None:
            message['ExtraContext'] = extra_context
        if extra_channel is not None:
            message['ExtraPriority'] = extra_priority
        return self.sendMessage(message)

    @ami_action
    def reload(self, module):
        """Send a reload event.

        :param module: Name of the module to reload
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'Reload',
            'Module': module
        })

    @ami_action
    def sendText(self, channel, message):
        """Send text message to channel while in a call.

        :param channel:
        :param message:
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'SendText',
            'Channel': channel,
            'Message': message
        })

    @ami_action
    def setVar(self, variable, value, channel=None):
        """Sets a channel variable or function value.

        This command can be used to set the value of channel variables or dialplan functions.
        If a channel name is not provided then the variable is considered global.

        :param channel:
        :param variable:
        :param value:
        :return: asyncio.Future
        """
        message = {
            'Action': 'SetVar',
            'Variable': variable,
            'Value': value
        }
        if channel:
            message['Channel'] = channel
        return self.sendMessage(message)

    @ami_action
    def showDialPlan(self, extension=None, context=None):
        """Show dialplan contexts and extensions

        :param extension: Show a specific extension
        :param context: Show a specific context
        :return: asyncio.Future
        """
        message = {
            'Action': 'ShowDialPlan'
        }
        if extension:
            message['Extension'] = extension
        if context:
            message['Context'] = context
        return self.sendMessage(message)

    @ami_action
    def sipNotify(self, channel, variables):
        """Send a SIP notify.

        :param channel: Peer to receive the notify
        :param variables: At least one variable pair must be specified. name=value
        :return: asyncio.Future
        """
        message = [
            ('Action', 'SIPNotify'),
            ('Channel', channel)
        ]
        for variable in variables.items():
            message.append(('Variable', '{0:s}={1:s}'.format(*variable)))
        return self.sendMessage(message)

    @ami_action
    def sipPeers(self):
        """List SIP peers (text format).

        Lists SIP peers in text format with details on current status.
        Peerlist will follow as separate events, followed by a final event called PeerlistComplete.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'SIPPeers'
        })

    @ami_action
    def sipQualifyPeer(self, peer):
        """Qualify a SIP peer.

        :param peer: The peer name you want to qualify
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'SIPQualifyPeer',
            'Peer': peer
        })

    @ami_action
    def sipShowPeer(self, peer):
        """Show one SIP peer with details on current status.

        :param peer: The peer name you want to check
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'SIPShowPeer',
            'Peer': peer
        })

    @ami_action
    def sipShowRegistry(self):
        """Show SIP registrations (text format)

        Lists all registration requests and status.
        Registrations will follow as separate events. followed by a final event called RegistrationsComplete.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'SIPShowRegistry'
        })

    @ami_action
    def status(self, channel=None, variables=None):
        """List channel status.

        Will return the status information of each channel along with the value for the specified channel variables.

        :param channel: The name of the channel to query for status
        :param variables: Comma , separated list of variable to include
        :return: asyncio.Future
        """
        message = {
            'Action': 'Status'
        }
        if channel:
            message['Channel'] = channel
        if variables:
            message['Variables'] = variables
        return self.sendMessage(message)

    @ami_action
    def stopMonitor(self, channel):
        """Stop monitoring a channel.

        This action may be used to end a previously started 'Monitor' action.

        :param channel: The name of the channel monitored
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'StopMonitor',
            'Channel': channel
        })

    @ami_action
    def unpauseMonitor(self, channel):
        """Unpause monitoring of a channel.

        This action may be used to re-enable recording of a channel after calling PauseMonitor.

        :param channel: Used to specify the channel to record
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'UnpauseMonitor',
            'Channel': channel
        })

    @ami_action
    def updateConfig(self, srcfile, dstfile, reload, headers=None):
        """Update basic configuration.

        This action will modify, create, or delete configuration elements in Asterisk configuration files.

        :param: srcfile: Configuration filename to read (e.g. foo.conf)
        :param: dstfile: Configuration filename to write (e.g. foo.conf)
        :param: reload: Whether or not a reload should take place (or name of specific module)
        :param: headers: should be a dictionary with the following keys:
                            Action-XXXXXX - Action to take.
                            X's represent 6 digit number beginning with 000000.
                                NewCat
                                RenameCat
                                DelCat
                                EmptyCat
                                Update
                                Delete
                                Append
                                Insert
                            Cat-XXXXXX - Category to operate on.
                            X's represent 6 digit number beginning with 000000.
                            Var-XXXXXX - Variable to work on.
                            X's represent 6 digit number beginning with 000000.
                            Value-XXXXXX - Value to work on.
                            X's represent 6 digit number beginning with 000000.
                            Match-XXXXXX - Extra match required to match line.
                            X's represent 6 digit number beginning with 000000.
                            Line-XXXXXX - Line in category to operate on (used with delete and insert actions).
                            X's represent 6 digit number beginning with 000000.
        :return: asyncio.Future
        """
        if not headers:
            headers = {}
        message = {
            'Action': 'updateconfig',
            'SrcFilename': srcfile,
            'DstFilename': dstfile,
            'Reload': 'yes' if reload in (True, 'yes', 1) else 'no'
        }
        message.update(headers)
        return self.sendMessage(message)

    @ami_action
    def userEvent(self, event, **kwargs):
        """Send an arbitrary event.

        :param event: Event string to send
        :param kwargs: header1, headerN ...
        :return: asyncio.Future
        """
        message = {
            'Action': 'UserEvent',
            'UserEvent': event
        }
        message.update(**kwargs)
        return self.sendMessage(message)

    @ami_action
    def voicemailUsersList(self):
        """List All Voicemail User Information.

        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'VoicemailUsersList'
        })

    @ami_action
    def waitEvent(self, timeout):
        """Wait for an event to occur.

        This action will elicit a Success response. Whenever a manager event is queued.
        Once WaitEvent has been called on an HTTP manager session, events will be generated and queued.

        :param timeout: Maximum time (in seconds) to wait for events, -1 means forever.
        :return: asyncio.Future
        """
        return self.sendMessage({
            'Action': 'WaitEvent',
            'Timeout': timeout
        })