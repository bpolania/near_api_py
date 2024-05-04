from typing import TypedDict, Callable, Any

class AssertionResponseResponse(TypedDict):
    authenticatorData: str
    clientDataJSON: str
    signature: str
    userHandle: str

class AssertionResponse(TypedDict):
    authenticatorAttachment: str  # 'platform' | 'cross-platform'
    getClientExtensionResults: Callable[[], Any]
    id: str
    rawId: str
    response: AssertionResponseResponse
    type: str  # 'public-key'
