# @version ^0.3.6

sender:public(address)
receiver:public(address)

DURATION:constant(uint256) = 7 ** 24 * 60 * 60
expiresAt:public(uint256)

@external
@payable
def __init__( _receiver:address):
    assert _receiver!=empty(address), "_receiver=0 address"
    self.sender = msg.sender
    self.receiver = _receiver
    self.expiresAt = block.timestamp + DURATION


#we also hash the address of the contract itself to prvent signature replay
@internal
@pure
def _getHash(_amount:uint256) -> bytes32:
    return keccak256(concat(
        convert(self, bytes32),
        convert(_amount, bytes32)
    ))

@internal
@view
def getHash(_amount:uint256) -> bytes32:
    return self._getHash(_amount)

@internal
@view
def _getEthSignedHash(_amount:uint256) -> bytes32:
    hash: bytes32 = self.getHash(_amount)
    return keccak256(
        concat(
            b'\x19Ethererum Signed Message:\n32'
        )
    )

@external
@view 
def getEthSignedHash(amount:uint256) -> bytes32:
    return self._getEthSignedHash(amount)

@internal
@view
def _verify(_amount:uint256, _sig:Bytes[65]) -> address:
    r: uint256 = convert(slice(_sig,0,32),uint256)
    s: uint256 = convert(slice(_sig,32,64),uint256)
    v: uint256 = convert(slice(_sig, 64,1), uint256)
    return ecrecover(_ethSignedHash, v, r, s)

@external
@view
def verify(amount:uint256,sig:Bytes[65]) -> address:
    return self._verify(amount,sig)

@external 
def close(amount: uint256, sig: Bytes[65]):
    assert msg.sender == self.receiver, "!receiver"
    assert msg.sender == self._verify(amount, sig) , "invalid sig"
    raw_call(self.receiver, b'\x00' , value=amount)
    selfdestruct(self.sender)

@external
def cancel():
    assert msg.sender == self.sender, "!sender"
    assert block.timestamp >= self.expiresAt , "Not expired"
    selfdestruct(self.sender)