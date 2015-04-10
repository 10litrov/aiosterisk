import asyncio
import logging
import re
from hashlib import md5

log = logging.getLogger('ami')


class AMICommandFailure(Exception):
    """AMI command failure"""


class AMIProtocol(asyncio.Protocol):
    def __init__(self, username, secret, instance_id=None, plaintext_login=True, loop=None):
        self.action_futures = {}
        self.event_handlers = {}

        self.transport = None
        self.hostname = None
        self.count = 0

        self.username = username
        self.secret = secret
        self.instance_id = instance_id
        self.plaintext_login = plaintext_login

        self.loop = loop or asyncio.get_event_loop()
        self.message_queue = asyncio.Queue(loop=self.loop)
        self.loop.create_task(self._dispatch_message())

    def connection_made(self, transport):
        log.info('Connection made to {0}:{1:d}'.format(*transport.get_extra_info('peername')))
        self.transport = transport
        self.hostname = '{0}:{1:d}'.format(*transport.get_extra_info('sockname'))
        self.loop.create_task(self.login())

    def data_received(self, data):
        # log.debug('Data received: {!r}'.format(data))
        self.message_queue.put_nowait(data.decode())

    def _dispatch_message(self):
        message = {}
        try:
            while True:
                # wait for next line
                line = yield from self.message_queue.get()
                for tag in line.splitlines():
                    if tag:
                        matches = re.match('^(\w+): (.+)$', tag)
                        if matches:  # it's a tag: value
                            message.update((matches.groups(),))
                        elif tag.startswith('Asterisk Call Manager') or tag == '--END COMMAND--':
                            pass
                        else:  # it's a command output or other plain text
                            message.setdefault('_', []).append(tag)
                    else:  # message ends
                        if message:
                            if 'ActionID' in message:
                                log.debug('Incoming message: {!r}'.format(message))
                                future = self.action_futures.get(message['ActionID'])
                                if future:
                                    if message.get('Response') == 'Error':
                                        future.set_exception(AMICommandFailure(message))
                                    else:
                                        future.set_result(message)
                                    del self.action_futures[message['ActionID']]
                            if 'Event' in message:
                                log.debug('Incoming event: {!r}'.format(message))
                                for event in self.event_handlers.get(message['Event'], []):
                                    self.loop.call_soon(event, message)
                            message.clear()  # prepare for the next message
        except asyncio.CancelledError:
            pass

    def _generateActionId(self):
        self.count += 1
        return '{0}-{1}-{2:d}'.format(self.hostname, id(self), self.count)

    def _loginPlainText(self):
        return self._sendMessage({
            'action': 'login',
            'username': self.username,
            'secret': self.secret
        })

    def _loginChallengeResponse(self):
        challenge = yield from self._sendMessage({
            'action': 'Challenge',
            'authtype': 'MD5'
        })
        log.info(challenge)
        # if 'challenge' not in challenge:
        #     raise
        key = md5('{0}{1}'.format(challenge['challenge'], self.secret).encode()).hexdigest()
        return self._sendMessage({
            'action': 'Login',
            'authtype': 'MD5',
            'username': self.username,
            'key': key
        })

    def _sendMessage(self, message):
        future = asyncio.Future(loop=self.loop)

        if type(message) == list:
            actionid = next((value for tag, value in message if tag.lower() == 'actionid'), None)
            data = message
        elif type(message) == dict:
            actionid = message.get('actionid', None)
            data = message.items()
        else:
            raise TypeError

        if actionid is None:
            actionid = self._generateActionId()

        for key, value in data:
            self.transport.write('{0:s}: {1:s}\n'.format(key.lower(), value).encode())
        self.transport.write('actionid: {:s}\n'.format(actionid).encode())
        self.transport.write('\n'.encode())

        self.action_futures[actionid] = future
        return future

    def on(self, event, callback):
        self.event_handlers.setdefault(event, []).append(callback)
        return self

    def off(self, event, callback):
        events = self.event_handlers.get(event, [])
        for i in [index for index, value in enumerate(events) if value == callback]:
            events.pop(i)
        return self

    def absoluteTimeout(self, channel, timeout):
        """Set timeout value for the given channel (in seconds)"""
        return self._sendMessage({
            'action': 'absoluteTimeout',
            'timeout': timeout,
            'channel': channel
        })

    def agentLogoff(self, agent, soft):
        """Logs off the specified agent for the queue system"""
        return self._sendMessage({
            'action': 'agentlogoff',
            'agent': agent,
            'soft': 'true' if soft in (True, 'yes', 1) else 'false'
        })

    def agents(self):
        """Retrieve agents information"""
        return self._sendMessage({
            'action': 'agents'
        })

    def agi(self, channel, command, command_id):
        """Add an AGI command to execute by Async AGI"""
        return self._sendMessage({
            'action': 'agi',
            'channel': channel,
            'command': command,
            'commandid': command_id
        })

    def atxfer(self, channel, exten, context, priority):
        """Attended transfer"""
        return self._sendMessage({
            'action': 'atxfer',
            'channel': channel,
            'exten': exten,
            'context': context,
            'priority': priority
        })

    def bridge(self, channel1, channel2, tone):
        """Bridge two channels already in the PBX"""
        return self._sendMessage({
            'action': 'bridge',
            'channel1': channel1,
            'channel2': channel2,
            'tone': 'yes' if tone in (True, 'yes', 1) else 'no'
        })

    def changeMonitor(self, channel, filename):
        """Change the file to which the channel is to be recorded"""
        return self._sendMessage({
            'action': 'changemonitor',
            'channel': channel,
            'filename': filename
        })

    def command(self, command):
        """Run asterisk CLI command, return deferred result for list of lines
        returns deferred returning list of lines (strings) of the command
        output.
        See listCommands to see available commands
        """
        return self._sendMessage({
            'action': 'command',
            'command': command
        })

    def dbDel(self, family, key):
        """Delete key value in the AstDB database"""
        return self._sendMessage({
            'action': 'dbdel',
            'family': family,
            'key': key
        })

    def dbDelTree(self, family, key=None):
        """Delete key value or key tree in the AstDB database"""
        message = {
            'action': 'dbdeltree',
            'family': family
        }
        if key is not None:
            message['key'] = key
        return self._sendMessage(message)

    def dbGet(self, family, key):
        """This action retrieves a value from the AstDB database"""
        return self._sendMessage({
            'action': 'dbget',
            'family': family,
            'key': key
        })

    def dbPut(self, family, key, value):
        """Sets a key value in the AstDB database"""
        return self._sendMessage({
            'action': 'dbput',
            'family': family,
            'key': key,
            'val': value
        })

    def events(self, eventmask=False):
        """Determine whether events are generated"""
        if eventmask in ('off', False, 0):
            eventmask = 'off'
        elif eventmask in ('on', True, 1):
            eventmask = 'on'
        # otherwise is likely a type-mask
        return self._sendMessage({
            'action': 'events',
            'eventmask': eventmask
        })

    def extensionState(self, exten, context):
        """Get extension state
        This command reports the extension state for the given extension.
        If the extension has a hint, this will report the status of the
        device connected to the extension.
        The following are the possible extension states:
        -2    Extension removed
        -1    Extension hint not found
         0    Idle
         1    In use
         2    Busy"""
        return self._sendMessage({
            'action': 'extensionstate',
            'exten': exten,
            'context': context
        })

    def getConfig(self, filename):
        """Retrieves the data from an Asterisk configuration file"""
        return self._sendMessage({
            'action': 'getconfig',
            'filename': filename
        })

    def getVar(self, variable, channel=None):
        """Retrieve the given variable from the channel.
        If channel is None, this gets a global variable."""
        message = {
            'action': 'getvar',
            'variable': variable
        }
        if channel:
            message['channel'] = channel
        return self._sendMessage(message)

    def hangup(self, channel):
        """Tell channel to hang up"""
        return self._sendMessage({
            'action': 'hangup',
            'channel': channel
        })

    def login(self):
        """Login into the AMI"""
        try:
            if self.plaintext_login:
                yield from self._loginPlainText()
            else:
                yield from self._loginChallengeResponse()
        except AMICommandFailure as e:
            log.error('Authentication failed')
            raise e
        else:
            log.info('Authentication succeded')

    def listCommands(self):
        """List the set of commands available
        Returns a single message with each command-name as a key
        """
        return self._sendMessage({
            'action': 'listcommands'
        })

    def logoff(self):
        """Log off from the manager instance"""
        return self._sendMessage({
            'action': 'logoff'
        })

    def mailboxCount(self, mailbox):
        """Get count of messages in the given mailbox"""
        return self._sendMessage({
            'action': 'mailboxcount',
            'mailbox': mailbox
        })

    def mailboxStatus(self, mailbox):
        """Get status of given mailbox"""
        return self._sendMessage({
            'action': 'mailboxstatus',
            'mailbox': mailbox
        })

    def meetmeMute(self, meetme, usernum):
        """Mute a user in a given meetme"""
        return self._sendMessage({
            'action': 'meetmemute',
            'meetme': meetme,
            'usernum': usernum
        })

    def meetmeUnmute(self, meetme, usernum):
        """ Unmute a specified user in a given meetme"""
        return self._sendMessage({
            'action': 'meetmeunmute',
            'meetme': meetme,
            'usernum': usernum
        })

    def monitor(self, channel, file, format, mix):
        """Record given channel to a file (or attempt to anyway)"""
        return self._sendMessage({
            'action': 'monitor',
            'channel': channel,
            'file': file,
            'format': format,
            'mix': mix
        })

    def originate(self, channel, context=None, exten=None, priority=None, timeout=None, callerid=None, account=None,
                  application=None, data=None, variables=None, async=False, channelid=None, otherchannelid=None):
        """Originate call to connect channel to given context/exten/priority
        channel -- the outgoing channel to which will be dialed
        context/exten/priority -- the dialplan coordinate to which to connect
            the channel (i.e. where to start the called person)
        timeout -- duration before timeout in seconds
                   (note: not Asterisk standard!)
        callerid -- callerid to display on the channel
        account -- account to which the call belongs
        application -- alternate application to Dial to use for outbound dial
        data -- data to pass to application
        variable -- variables associated to the call
        async -- make the origination asynchronous
        """
        if not variables:
            variables = {}
        message = [(k, v) for k, v in (
            ('action', 'originate'),
            ('channel', channel),
            ('context', context),
            ('exten', exten),
            ('priority', priority),
            ('callerid', callerid),
            ('account', account),
            ('application', application),
            ('data', data),
            ('async', str(async)),
            ('channelid', channelid),
            ('otherchannelid', otherchannelid))
            if v is not None]
        if timeout is not None:
            message['timeout'] = timeout*1000
        for variable in variables.items():
            message.append(('variable', '{0:s}={1:s}'.format(*variable)))
        return self._sendMessage(message)

    def park(self, channel, channel2, timeout):
        """Park channel"""
        return self._sendMessage({
            'action': 'park',
            'channel': channel,
            'channel2': channel2,
            'timeout': timeout
        })

    def parkedCall(self):
        """Check for a ParkedCall event"""
        return self._sendMessage({
            'action': 'parkedcall'
        })

    def unParkedCall(self):
        """Check for an UnParkedCall event """
        return self._sendMessage({
            'action': 'unparkedcall'
        })

    def parkedCalls(self):
        """Retrieve set of parked calls via multi-event callback"""
        return self._sendMessage({
            'action': 'parkedcalls'
        })

    def pauseMonitor(self, channel):
        """Temporarily stop recording the channel"""
        return self._sendMessage({
            'action': 'pausemonitor',
            'channel': channel
        })

    def ping(self):
        """Check to see if the manager is alive..."""
        return self._sendMessage({
            'action': 'ping'
        })

    def playDTMF(self, channel, digit):
        """Play DTMF on a given channel"""
        return self._sendMessage({
            'action': 'playdtmf',
            'channel': channel,
            'digit': digit
        })

    def queueAdd(self, queue, interface, penalty=0, paused=True,
                 membername=None, stateinterface=None):
        """Add given interface to named queue"""
        message = {
            'action': 'queueadd',
            'queue': queue,
            'interface': interface,
            'penalty': penalty,
            'paused': 'true' if paused in (True, 'true', 1) else 'false'
        }
        if membername is not None:
            message['membername'] = membername
        if stateinterface is not None:
            message['stateinterface'] = stateinterface
        return self._sendMessage(message)

    def queueLog(self, queue, event, uniqueid=None, interface=None, msg=None):
        """Adds custom entry in queue_log"""
        message = {
            'action': 'queuelog',
            'queue': queue,
            'event': event
        }
        if uniqueid is not None:
            message['uniqueid'] = uniqueid
        if interface is not None:
            message['interface'] = interface
        if msg is not None:
            message['message'] = msg
        return self._sendMessage(message)

    def queuePause(self, queue, interface, paused=True, reason=None):
        """Pause/Play named queue"""
        message = {
            'action': 'queuepause',
            'queue': queue,
            'interface': interface,
            'paused': 'true' if paused in (True, 'true', 1) else 'false'
        }
        if reason is not None:
            message['reason'] = reason
        return self._sendMessage(message)

    def queuePenalty(self, interface, penalty, queue=None):
        """Set penalty for interface"""
        message = {
            'action': 'queuepenalty',
            'interface': interface,
            'penalty': penalty
        }
        if queue is not None:
            message.update({'queue': queue})
        return self._sendMessage(message)

    def queueRemove(self, queue, interface):
        """Remove given interface from named queue"""
        return self._sendMessage({
            'action': 'queueremove',
            'queue': queue,
            'interface': interface
        })

    def queues(self):
        """Retrieve information about active queues via multiple events"""
        # XXX AMI returns improperly formatted lines so this doesn't work now.
        return self._sendMessage({
            'action': 'queues'
        })

    def queueStatus(self, queue=None, member=None):
        """Retrieve information about active queues via multiple events"""
        message = {
            'action': 'queuestatus'
        }
        if queue is not None:
            message.update({'queue': queue})
        if member is not None:
            message.update({'member': member})
        return self._sendMessage(message)

    def redirect(self, channel, context, exten, priority, extra_channel=None):
        """Transfer channel(s) to given context/exten/priority"""
        message = {
            'action': 'redirect',
            'channel': channel,
            'context': context,
            'exten': exten,
            'priority': priority,
        }
        if extra_channel is not None:
            message['extrachannel'] = extra_channel
        return self._sendMessage(message)

    def setCDRUserField(self, channel, userField, append=True):
        """Set/add to a user field in the CDR for given channel"""
        return self._sendMessage({
            'channel': channel,
            'userfield': userField,
            'append': 'true' if append in (True, 'true', 1) else 'false',
        })

    def setVar(self, channel, variable, value):
        """Set channel variable to given value.
        If channel is None, this sets a global variable."""
        message = {
            'action': 'setvar',
            'variable': variable,
            'value': value
        }
        # channel is optional
        if channel:
            message['channel'] = channel
        return self._sendMessage(message)

    def sipPeers(self):
        """List all known sip peers"""
        return self._sendMessage({
            'action': 'sippeers'
        })

    def sipShowPeers(self, peer):
        return self._sendMessage({
            'action': 'sipshowpeer',
            'peer': peer
        })

    def status(self, channel=None):
        """Retrieve status for the given (or all) channels
        The results come in via multi-event callback
        channel -- channel name or None to retrieve all channels
        returns deferred returning list of Status Events for each requested
        channel
        """
        message = {
            'action': 'status'
        }
        if channel:
            message['channel'] = channel
        return self._sendMessage(message)

    def stopMonitor(self, channel):
        """Stop monitoring the given channel"""
        return self._sendMessage({
            'action': 'monitor',
            'channel': channel
        })

    def unpauseMonitor(self, channel):
        """Resume recording a channel"""
        return self._sendMessage({
            'action': 'unpausemonitor',
            'channel': channel
        })

    def updateConfig(self, srcfile, dstfile, reload, headers=None):
        """Update a configuration file
        headers should be a dictionary with the following keys
        Action-XXXXXX
        Cat-XXXXXX
        Var-XXXXXX
        Value-XXXXXX
        Match-XXXXXX
        """
        if not headers:
            headers = {}
        message = {
            'action': 'updateconfig',
            'srcfilename': srcfile,
            'dstfilename': dstfile,
            'reload': 'yes' if reload in (True, 'yes', 1) else 'no'
        }
        message.update(headers)
        return self._sendMessage(message)

    def userEvent(self, event, **kwargs):
        """Sends an arbitrary event to the Asterisk Manager Interface."""
        message = {
            'action': 'userevent',
            'userevent': event
        }
        message.update(**kwargs)
        return self._sendMessage(message)

    def waitEvent(self, timeout):
        """Waits for an event to occur
        After calling this action, Asterisk will send you a Success response as
        soon as another event is queued by the AMI
        """
        return self._sendMessage({
            'action': 'waitevent',
            'timeout': timeout
        })

    def dahdiDNDoff(self, channel):
        """Toggles the DND state on the specified DAHDI channel to off"""
        return self._sendMessage({
            'action': 'dahdidndoff',
            'channel': channel
        })

    def dahdiDNDon(self, channel):
        """Toggles the DND state on the specified DAHDI channel to on"""
        return self._sendMessage({
            'action': 'dahdidndon',
            'channel': channel
        })

    def dahdiDialOffhook(self, channel, number):
        """Dial a number on a DAHDI channel while off-hook"""
        return self._sendMessage({
            'action': 'dahdidialoffhook',
            'dahdichannel': channel,
            'number': number
        })

    def dahdiHangup(self, channel):
        """Hangs up the specified DAHDI channel"""
        return self._sendMessage({
            'action': 'dahdihangup',
            'dahdichannel': channel
        })

    def dahdiRestart(self, channel):
        """Restarts the DAHDI channels, terminating any calls in progress"""
        return self._sendMessage({
            'action': 'dahdirestart',
            'dahdichannel': channel
        })

    def dahdiShowChannels(self):
        """List all DAHDI channels"""
        return self._sendMessage({
            'action': 'dahdishowchannels'
        })

    def dahdiTransfer(self, channel):
        """Transfers DAHDI channel"""
        return self._sendMessage({
            'action': 'dahditransfer',
            'channel': channel
        })
