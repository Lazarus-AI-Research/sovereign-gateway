#![cfg(feature = "test-utils")]

use greater_spire::{AuthenticatedPeer, SpiffeId};

#[test]
fn synthetic_peer_can_be_injected_into_request_extensions() {
    let spiffe_id: SpiffeId = "spiffe://fleet.test/service/nexis".try_into().unwrap();
    let expires_at_unix = 4_102_444_800;
    let peer = AuthenticatedPeer::for_test(spiffe_id.clone(), expires_at_unix);
    let mut request = http::Request::new(());
    request.extensions_mut().insert(peer.clone());

    let extracted = request.extensions().get::<AuthenticatedPeer>().unwrap();
    assert_eq!(extracted, &peer);
    assert_eq!(extracted.spiffe_id(), &spiffe_id);
    assert_eq!(extracted.expires_at_unix(), expires_at_unix);
}

#[test]
fn synthetic_peer_preserves_expired_timestamps() {
    let spiffe_id: SpiffeId = "spiffe://fleet.test/service/nexis".try_into().unwrap();
    for expires_at_unix in [-1, 0, 1] {
        let peer = AuthenticatedPeer::for_test(spiffe_id.clone(), expires_at_unix);
        assert_eq!(peer.spiffe_id(), &spiffe_id);
        assert_eq!(peer.expires_at_unix(), expires_at_unix);
    }
}
