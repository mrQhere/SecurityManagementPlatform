"""
In-Process Event Bus V7.0.8
==========================
Thread-safe publish/subscribe event bus replacing the old unsafe UDP IPC socket.
Allows decoupled communication between scanner threads and the UI.

Usage:
    # Publisher (scanner thread):
    from tools import event_bus
    event_bus.emit("mac_changed", {"new_mac": "aa:bb:cc:dd:ee:ff"})

    # Subscriber (dashboard):
    from tools import event_bus
    event_bus.subscribe("mac_changed", my_callback)
"""
import threading
import logging

logger = logging.getLogger("smp")

_subscriptions: dict = {}
_lock = threading.Lock()


def subscribe(event: str, callback):
    """Register a callback for an event. Callback receives (event, data) args."""
    with _lock:
        if event not in _subscriptions:
            _subscriptions[event] = []
        if callback not in _subscriptions[event]:
            _subscriptions[event].append(callback)


def unsubscribe(event: str, callback):
    """Remove a callback for an event."""
    with _lock:
        if event in _subscriptions:
            try:
                _subscriptions[event].remove(callback)
            except ValueError:
                pass


def emit(event: str, data: dict = None):
    """
    Emit an event to all registered subscribers.
    Callbacks are called in the emitter's thread — subscribers that
    need to update Qt UI must use Qt signals to marshal to the main thread.
    """
    with _lock:
        callbacks = list(_subscriptions.get(event, []))

    for cb in callbacks:
        try:
            cb(event, data or {})
        except Exception as e:
            logger.error(f"[EventBus] Error in subscriber for event '{event}': {e}")


def clear():
    """Clear all subscriptions (used in tests)."""
    with _lock:
        _subscriptions.clear()
