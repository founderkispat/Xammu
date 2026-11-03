package report

import "xammu/internal/contracts"

// The contract layer keeps its ladder arithmetic private, so ordering is re-declared
// here from the declared vocabularies rather than guessed at. If a level or a claim is
// added to contracts and not to these lists it ranks as -1, which makes it the weakest
// thing in the report: an unranked rung cannot inflate a summary.
func levelRank(l contracts.EvidenceLevel) int {
	for i, v := range contracts.AllEvidenceLevels() {
		if v == l {
			return i
		}
	}
	return -1
}

func claimRank(c contracts.ClaimType) int {
	for i, v := range contracts.AllClaimTypes() {
		if v == c {
			return i
		}
	}
	return -1
}
