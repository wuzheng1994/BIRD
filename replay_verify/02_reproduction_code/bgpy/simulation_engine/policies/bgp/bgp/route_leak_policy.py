from bgpy.simulation_engine.policies.bgp.bgp import BGP
from bgpy.shared.enums import Relationships


class RouteLeakPolicy(BGP):

    """
    Simulate provider-to-peer route leak.

    AS49981 leaks routes learned from provider
    to providers and peers.
    """

    def _policy_propagate(
        self,
        neighbor,
        ann,
        propagate_to,
        send_rels,
    ):

        # Only AS49981 performs the leak
        if self.as_.asn == 49981:

            # Leak provider learned routes
            if (
                ann.recv_relationship
                == Relationships.PROVIDERS
            ):

                # send to providers
                # or peers
                if propagate_to in (
                    Relationships.PROVIDERS,
                    Relationships.PEERS,
                ):

                    self._process_outgoing_ann(
                        neighbor,
                        ann,
                        propagate_to,
                        send_rels,
                    )

                    return True


        return False