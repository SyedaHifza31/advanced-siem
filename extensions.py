"""
Extensions - Shared database session factory.
Yahan se saari files get_session() call karti hain.
"""
 
_SessionFactory = None
 
 
def init_session_factory(session_factory):
    """main.py se call hota hai, Session factory store karta hai."""
    global _SessionFactory
    _SessionFactory = session_factory
 
 
def get_session():
    """Naya DB session return karta hai."""
    if _SessionFactory is None:
        raise RuntimeError("Session factory initialized nahi hui. main.py check karo.")
    return _SessionFactory()