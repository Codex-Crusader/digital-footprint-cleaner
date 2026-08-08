"""Structural type for the HTTP client the probe modules depend on.

The probes in :mod:`utils.email_signals` and :mod:`utils.username_check` take an
injectable client so the test suite can run without touching the network. They
were originally annotated ``httpx.Client``, which was wrong in a small but real
way: they do not need an ``httpx.Client``, they need *something that can GET*.
Naming the concrete class forced every test double to masquerade as one, which
type checkers correctly objected to.

:class:`HttpClient` describes exactly the surface the probes use and nothing
more, so ``httpx.Client`` satisfies it structurally without being named, and so
does any hand-written fake. This is dependency inversion in the ordinary sense:
the caller owns the interface, not the library.

Keep this protocol minimal. Every method added here is a method every test
double must grow, and every keyword argument added is one more thing an injected
client is required to accept.
"""

from typing import Any, Protocol


class HttpClient(Protocol):
    """The subset of ``httpx.Client`` the probe modules actually call.

    ``params``, ``headers`` and ``timeout`` are typed ``Any`` deliberately:
    httpx accepts a wide union for each (mappings, sequences of pairs, its own
    ``Timeout`` object), and restating that union here would buy nothing and
    break the moment httpx widened it.

    Return type is ``Any`` rather than ``httpx.Response`` so a fake may return a
    minimal stand-in. Callers that need the real thing re-narrow with their own
    return annotation.
    """

    def get(
        self,
        url: str,
        *,
        params: Any = ...,
        headers: Any = ...,
        timeout: Any = ...,
        follow_redirects: bool = ...,
    ) -> Any:
        """Issue a GET request."""
        ...

    def close(self) -> None:
        """Release any pooled connections."""
        ...
