package WASB {
    private import ScalarValues::*;

    /* Content that changes only through a signed commit. Lives under .wasb/model/user/. */
    metadata def UserDeclared;

    /* A proposal that has not been accepted. */
    metadata def AgentSuggested;

    /* Points at a concrete region: kind says how path and id are read. */
    metadata def Anchor {
        attribute path : String;
        attribute kind : String;
        attribute id : String;
    }

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

    metadata def EvidenceClass {
        attribute evidence : EvidenceClassKind;
    }

    /* The anchored region is no longer claimed by the model. */
    metadata def Detached;

    /* An acknowledged checker limitation. */
    metadata def KnownGap {
        attribute reason : String;
    }
}
