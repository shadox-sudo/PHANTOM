class PhantomError(Exception):
    pass

class TargetUnreachable(PhantomError):
    pass

class RateLimitHit(PhantomError):
    pass

class ModuleLoadError(PhantomError):
    pass

class ExploitFailed(PhantomError):
    pass
