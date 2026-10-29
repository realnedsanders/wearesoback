package WASB {
    private import ScalarValues::*;

    /* Content that changes only through a signed commit. Lives under .wasb/model/user/. */
    metadata def UserDeclared;

    /* A proposal that has not been accepted. The model tree must not carry it. */
    metadata def AgentSuggested;

    /* Points at a concrete region: kind says how path and id are read. */
    metadata def Anchor {
        attribute path : String;
        attribute kind : String;
        attribute id : String;
    }

    /* lastHash is the anchored target's structural hash. generatedFraction, when set,
       is the lowest generated fraction the target may drop to. */
    metadata def Coverage {
        attribute generatedFraction : Real;
        attribute lastHash : String;
    }

    enum def EvidenceClassKind {
        enum structural;
        enum staticAnalysis;
        enum runtimeObservation;
        enum manual;
    }

    /* Mandatory on requirements. Only structural requirements are discharged by the model. */
    metadata def EvidenceClass {
        attribute evidence : EvidenceClassKind;
    }

    /* The anchored region is no longer claimed by the model. */
    metadata def Detached;

    /* An acknowledged checker limitation. */
    metadata def KnownGap {
        attribute reason : String;
    }

    /* kinds */
    /* What wasb itself does not see. */
    part def Checker {
        @KnownGap { reason = "Helm templates are hashed whole: any edit to a template is drift."; }
        @KnownGap { reason = "UDS Package CRs inside Helm templates are read with template directives blanked, so every branch counts and templated values are unknown."; }
        @KnownGap { reason = "Only satisfy assertions are evaluated; asserted constraints outside them are not."; }
        @KnownGap { reason = "Requirements of evidence class staticAnalysis, runtimeObservation or manual are reported, never discharged: no collector exists yet."; }
        @KnownGap { reason = "Generated Go stubs carry no imports; run goimports after wasb generate."; }
        @KnownGap { reason = "Only Go, zarf.yaml, Helm templates, UDS Package CRs, UDS tasks and GitHub Actions jobs are scanned."; }
    }
}
