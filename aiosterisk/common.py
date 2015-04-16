def ami_action(func):
    """AMI action decorator"""
    func._is_ami_action = True
    return func


def is_ami_action(func):
    return getattr(func, '_is_ami_action', False)


class AMICommandFailure(Exception):
    """AMI command failure"""