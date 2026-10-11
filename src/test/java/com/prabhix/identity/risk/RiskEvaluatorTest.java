package com.prabhix.identity.risk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RiskEvaluatorTest {

    private final RiskEvaluator risk = new RiskEvaluator();

    @Test
    @DisplayName("a staff address that only changes inside the same /24 stays signed in")
    void staffSameIpv4PrefixIsAllowed() {
        assertThat(risk.networkChange(true, "203.0.113.10", "203.0.113.44"))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
    }

    @Test
    @DisplayName("a staff move to another /24 still asks for a fresh proof")
    void staffDifferentIpv4PrefixStepsUp() {
        assertThat(risk.networkChange(true, "203.0.113.10", "198.51.100.10"))
                .isEqualTo(RiskEvaluator.Decision.STEP_UP);
    }

    @Test
    @DisplayName("an IPv6 privacy address in the same /64 is the same network")
    void staffSameIpv6PrefixIsAllowed() {
        assertThat(risk.networkChange(true, "2001:db8:1:2::1", "2001:db8:1:2:abcd::9"))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
    }

    @Test
    @DisplayName("a different IPv6 /64 asks a staff session for a fresh proof")
    void staffDifferentIpv6PrefixStepsUp() {
        assertThat(risk.networkChange(true, "2001:db8:1:2::1", "2001:db8:1:3::1"))
                .isEqualTo(RiskEvaluator.Decision.STEP_UP);
    }

    @Test
    @DisplayName("an IPv4-mapped address is the same network as its dotted form")
    void mappedIpv4MatchesDottedForm() {
        assertThat(risk.networkChange(true, "203.0.113.10", "::ffff:203.0.113.44"))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
    }

    @Test
    @DisplayName("everyone else stays signed in even when the network prefix changes")
    void regularUserNetworkChangeIsAllowed() {
        assertThat(risk.networkChange(false, "203.0.113.10", "198.51.100.10"))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
    }

    @Test
    @DisplayName("a missing address is not a change")
    void blankAddressIsAllowed() {
        assertThat(risk.networkChange(true, null, "203.0.113.10"))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
        assertThat(risk.networkChange(true, "203.0.113.10", " "))
                .isEqualTo(RiskEvaluator.Decision.ALLOW);
    }

    @Test
    @DisplayName("an address that is not a literal still asks staff for a fresh proof")
    void unparseableStaffAddressStepsUp() {
        assertThat(risk.networkChange(true, "203.0.113.10", "not-an-address"))
                .isEqualTo(RiskEvaluator.Decision.STEP_UP);
    }
}
