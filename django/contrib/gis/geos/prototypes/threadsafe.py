import threading
from django.contrib.gis.geos.libgeos import lgeos, notice_h, error_h, CONTEXT_PTR

class GEOSContextHandle(object):
    """
    Python object representing a GEOS context handle.
    """
    def __init__(self):
        # Initializing the context handler for this thread with
        # the notice and error handler.
        self.ptr = lgeos.initGEOS_r(notice_h, error_h)

    def __del__(self):
        if self.ptr:
            lgeos.finishGEOS_r(self.ptr)

# Defining a thread-local object and creating an instance
# to hold a reference to GEOSContextHandle for this thread.
class GEOSContext(threading.local):
    handle = None

thread_context = GEOSContext()

class GEOSFunc(object):
    """
    Class that serves as a wrapper for GEOS C Functions, and will
    use thread-safe function variants when available.
    """
    def __init__(self, func_name):
        try:
            # GEOS thread-safe function signatures end with '_r', and
            # take an additional context handle parameter.
            self.cfunc = getattr(lgeos, func_name + '_r')
            self.threaded = True
            # Create a reference here to thread_context so it's not
            # garbage-collected before an attempt to call this object.
            self.thread_context = thread_context
        except AttributeError:
            # Otherwise, use usual function.
            self.cfunc = getattr(lgeos, func_name)
            self.threaded = False

    def __call__(self, *args):
        if self.threaded:
            # If a context handle does not exist for this thread, initialize one.
            if not self.thread_context.handle:
                self.thread_context.handle = GEOSContextHandle()
            # Call the threaded GEOS routine with pointer of the context handle
            # as the first argument.
            return self.cfunc(self.thread_context.handle.ptr, *args)
        else:
            return self.cfunc(*args)

    def __str__(self):
        return self.cfunc.__name__

    @property
    def argtypes(self):
        return self.cfunc.argtypes

    @argtypes.setter
    def argtypes(self, argtypes):
        if self.threaded:
            new_argtypes = [CONTEXT_PTR]
            new_argtypes.extend(argtypes)
            self.cfunc.argtypes = new_argtypes
        else:
            self.cfunc.argtypes = argtypes

    @property
    def restype(self):
        return self.cfunc.restype

    @restype.setter
    def restype(self, restype):
        self.cfunc.restype = restype

    @property
    def errcheck(self):
        return self.cfunc.errcheck

    @errcheck.setter
    def errcheck(self, errcheck):
        self.cfunc.errcheck = errcheck
