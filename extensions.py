_SessionFactory = None
 
 
def init_session_factory(session_factory)
    global _SessionFactory
    _SessionFactory = session_factory
 
 
def get_session():
    if _SessionFactory is None:
        raise RuntimeError
    return _SessionFactory()
