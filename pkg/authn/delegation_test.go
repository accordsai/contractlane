package authn

import (
	"testing"
	"time"
)

func TestDelegationScopeAllows_ContractExecuteGranted(t *testing.T) {
	now := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)
	ok := delegationScopeAllows(now, "contract.execute", "tpl_nda_us_v1", "LOW", []string{"contract.execute"}, nil, "", nil, nil)
	if !ok {
		t.Fatalf("expected delegation to grant contract.execute")
	}
}

func TestDelegationScopeAllows_ExpiredDenied(t *testing.T) {
	now := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)
	exp := now.Add(-1 * time.Minute)
	ok := delegationScopeAllows(now, "contract.execute", "tpl_nda_us_v1", "LOW", []string{"contract.execute"}, nil, "", &exp, nil)
	if ok {
		t.Fatalf("expected expired delegation to deny")
	}
}

func TestDelegationScopeAllows_RevokedDenied(t *testing.T) {
	now := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)
	revoked := now.Add(-1 * time.Minute)
	ok := delegationScopeAllows(now, "contract.execute", "tpl_nda_us_v1", "LOW", []string{"contract.execute"}, nil, "", nil, &revoked)
	if ok {
		t.Fatalf("expected revoked delegation to deny")
	}
}

func TestDelegationScopeAllows_TemplateMismatchDenied(t *testing.T) {
	now := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)
	ok := delegationScopeAllows(now, "contract.execute", "tpl_sales_v1", "LOW", []string{"contract.execute"}, []string{"tpl_nda_us_v1"}, "", nil, nil)
	if ok {
		t.Fatalf("expected template mismatch to deny")
	}
}

func TestDelegationScopeAllows_RiskMismatchDenied(t *testing.T) {
	now := time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC)
	ok := delegationScopeAllows(now, "contract.execute", "tpl_nda_us_v1", "HIGH", []string{"contract.execute"}, nil, "MEDIUM", nil, nil)
	if ok {
		t.Fatalf("expected risk mismatch to deny")
	}
}
