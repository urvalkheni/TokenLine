"""
Reproducible Detection Evaluation Framework for TokenLine.

Provides standardized incident-level evaluation of TokenLine's production detection engine.
Calculates TP, FP, TN, FN, Precision, Recall, Specificity, and F1-score across all rules,
handling zero-denominator cases explicitly (None / "N/A", never invented).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import json

from backend.correlator.models import (
    AlertRecord,
    RULE_TOKEN_REUSE,
    RULE_REVOKED_USE,
    RULE_EXPIRED_USE,
    RULE_CONCURRENT_USE,
    RULE_IMPOSSIBLE_TRAVEL,
    RULE_TITLES,
)
from backend.correlator.engine import TokenFamilyCorrelator
from simulator.evaluation_datasets import LabeledIncident


@dataclass
class EvaluationMetrics:
    """
    Standardized classification performance metrics.
    Zero-denominator edge cases are explicitly represented as None.
    """
    tp: int
    fp: int
    tn: int
    fn: int
    precision: Optional[float]
    recall: Optional[float]
    specificity: Optional[float]
    f1_score: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall": round(self.recall, 4) if self.recall is not None else None,
            "specificity": round(self.specificity, 4) if self.specificity is not None else None,
            "f1_score": round(self.f1_score, 4) if self.f1_score is not None else None,
            "precision_display": f"{self.precision:.1%}" if self.precision is not None else "N/A",
            "recall_display": f"{self.recall:.1%}" if self.recall is not None else "N/A",
            "specificity_display": f"{self.specificity:.1%}" if self.specificity is not None else "N/A",
            "f1_display": f"{self.f1_score:.1%}" if self.f1_score is not None else "N/A",
        }


def calculate_metrics(tp: int, fp: int, tn: int, fn: int) -> EvaluationMetrics:
    """
    Calculates precision, recall, specificity, and F1-score.
    Explicitly handles zero-denominator edge cases by returning None.
    """
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None

    if precision is not None and recall is not None and (precision + recall) > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
    else:
        f1_score = None

    return EvaluationMetrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        specificity=specificity,
        f1_score=f1_score,
    )


@dataclass
class IncidentEvaluationResult:
    """Evaluation outcome for a single incident case."""
    case_id: str
    category: str
    expected_label: str
    expected_rule: Optional[str]
    detected_alert: bool
    detected_rules: List[str]
    is_tp: bool
    is_fp: bool
    is_tn: bool
    is_fn: bool
    alerts: List[AlertRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "expected_label": self.expected_label,
            "expected_rule": self.expected_rule,
            "detected_alert": self.detected_alert,
            "detected_rules": self.detected_rules,
            "outcome": (
                "TP" if self.is_tp else ("FP" if self.is_fp else ("TN" if self.is_tn else "FN"))
            ),
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
        }


@dataclass
class EvaluationReport:
    """Comprehensive evaluation report across all incidents and detection rules."""
    incident_results: List[IncidentEvaluationResult]
    aggregate_metrics: EvaluationMetrics
    rule_metrics: Dict[str, EvaluationMetrics]
    total_incidents: int
    normal_incidents: int
    attack_incidents: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_incidents": self.total_incidents,
            "normal_incidents": self.normal_incidents,
            "attack_incidents": self.attack_incidents,
            "aggregate_metrics": self.aggregate_metrics.to_dict(),
            "rule_metrics": {k: v.to_dict() for k, v in self.rule_metrics.items()},
            "incidents": [r.to_dict() for r in self.incident_results],
        }

    def generate_markdown_report(self) -> str:
        """Renders GitHub Flavored Markdown table summary of evaluation results."""
        lines = [
            "# TokenLine Detection Engine Evaluation Report",
            "",
            f"**Total Incidents Evaluated:** {self.total_incidents} ({self.normal_incidents} Normal / {self.attack_incidents} Attack)",
            "",
            "## 1. Aggregate Incident-Level Detection Metrics",
            "",
            "| Metric | Value | Definition |",
            "| :--- | :--- | :--- |",
            f"| **True Positives (TP)** | `{self.aggregate_metrics.tp}` | Attack incidents correctly detected |",
            f"| **False Positives (FP)** | `{self.aggregate_metrics.fp}` | Benign incidents incorrectly alerted |",
            f"| **True Negatives (TN)** | `{self.aggregate_metrics.tn}` | Benign incidents correctly accepted without alerts |",
            f"| **False Negatives (FN)** | `{self.aggregate_metrics.fn}` | Attack incidents missed |",
            f"| **Precision** | `{self.aggregate_metrics.to_dict()['precision_display']}` | `TP / (TP + FP)` |",
            f"| **Recall (Sensitivity)** | `{self.aggregate_metrics.to_dict()['recall_display']}` | `TP / (TP + FN)` |",
            f"| **Specificity** | `{self.aggregate_metrics.to_dict()['specificity_display']}` | `TN / (TN + FP)` |",
            f"| **F1-Score** | `{self.aggregate_metrics.to_dict()['f1_display']}` | Harmonic mean of Precision and Recall |",
            "",
            "## 2. Per-Rule Detection Performance",
            "",
            "| Rule ID | Rule Title | TP | FP | TN | FN | Precision | Recall | Specificity | F1-Score |",
            "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]

        for rule_id, m in self.rule_metrics.items():
            title = RULE_TITLES.get(rule_id, rule_id)
            d = m.to_dict()
            lines.append(
                f"| `{rule_id}` | {title} | {m.tp} | {m.fp} | {m.tn} | {m.fn} | "
                f"{d['precision_display']} | {d['recall_display']} | {d['specificity_display']} | {d['f1_display']} |"
            )

        lines.extend([
            "",
            "## 3. Incident Breakdown",
            "",
            "| Incident ID | Category | Expected Label | Expected Rule | Detected Rules | Outcome |",
            "| :--- | :--- | :--- | :--- | :--- | :---: |",
        ])

        for r in self.incident_results:
            det = ", ".join(f"`{k}`" for k in r.detected_rules) if r.detected_rules else "None"
            exp = f"`{r.expected_rule}`" if r.expected_rule else "None"
            outcome = "✅ TP" if r.is_tp else ("❌ FP" if r.is_fp else ("✅ TN" if r.is_tn else "❌ FN"))
            lines.append(f"| `{r.case_id}` | {r.category} | {r.expected_label} | {exp} | {det} | {outcome} |")

        return "\n".join(lines)


def evaluate_incident(
    incident: LabeledIncident,
    correlator: Optional[TokenFamilyCorrelator] = None,
) -> IncidentEvaluationResult:
    """
    Evaluates a single incident against a fresh or provided correlator instance.
    Processes all events in the incident sequence and compares generated alerts with ground truth.
    """
    c = correlator if correlator is not None else TokenFamilyCorrelator()

    for event in incident.events:
        c.process_event(event)

    alerts = c.get_alerts()
    detected_rules = list({a.rule_id for a in alerts})
    has_alert = len(alerts) > 0

    is_tp = False
    is_fp = False
    is_tn = False
    is_fn = False

    if incident.is_attack:
        if incident.expected_rule:
            if incident.expected_rule in detected_rules:
                is_tp = True
            else:
                is_fn = True
        else:
            if has_alert:
                is_tp = True
            else:
                is_fn = True
    else:
        if has_alert:
            is_fp = True
        else:
            is_tn = True

    return IncidentEvaluationResult(
        case_id=incident.case_id,
        category=incident.category,
        expected_label=incident.expected_label,
        expected_rule=incident.expected_rule,
        detected_alert=has_alert,
        detected_rules=detected_rules,
        is_tp=is_tp,
        is_fp=is_fp,
        is_tn=is_tn,
        is_fn=is_fn,
        alerts=alerts,
    )


def evaluate_dataset(
    dataset: List[LabeledIncident],
    correlator_factory: Optional[Callable[[], TokenFamilyCorrelator]] = None,
) -> EvaluationReport:
    """
    Evaluates an entire dataset of labeled incidents.
    Aggregates metrics at the incident level and breaks down performance per detection rule.
    """
    factory = correlator_factory or (lambda: TokenFamilyCorrelator())
    results: List[IncidentEvaluationResult] = []

    for incident in dataset:
        c = factory()
        res = evaluate_incident(incident, correlator=c)
        results.append(res)

    # 1. Aggregate incident metrics
    agg_tp = sum(1 for r in results if r.is_tp)
    agg_fp = sum(1 for r in results if r.is_fp)
    agg_tn = sum(1 for r in results if r.is_tn)
    agg_fn = sum(1 for r in results if r.is_fn)
    aggregate_metrics = calculate_metrics(agg_tp, agg_fp, agg_tn, agg_fn)

    # 2. Per-rule metrics
    all_rules = [
        RULE_TOKEN_REUSE,
        RULE_REVOKED_USE,
        RULE_EXPIRED_USE,
        RULE_CONCURRENT_USE,
        RULE_IMPOSSIBLE_TRAVEL,
    ]

    rule_metrics: Dict[str, EvaluationMetrics] = {}
    for rule_id in all_rules:
        r_tp = 0
        r_fp = 0
        r_tn = 0
        r_fn = 0

        for r in results:
            expected_this_rule = (r.expected_rule == rule_id)
            detected_this_rule = (rule_id in r.detected_rules)

            if expected_this_rule and detected_this_rule:
                r_tp += 1
            elif not expected_this_rule and detected_this_rule:
                r_fp += 1
            elif not expected_this_rule and not detected_this_rule:
                r_tn += 1
            elif expected_this_rule and not detected_this_rule:
                r_fn += 1

        rule_metrics[rule_id] = calculate_metrics(r_tp, r_fp, r_tn, r_fn)

    total_incidents = len(results)
    normal_incidents = sum(1 for r in results if not r.expected_label.lower() == "attack")
    attack_incidents = sum(1 for r in results if r.expected_label.lower() == "attack")

    return EvaluationReport(
        incident_results=results,
        aggregate_metrics=aggregate_metrics,
        rule_metrics=rule_metrics,
        total_incidents=total_incidents,
        normal_incidents=normal_incidents,
        attack_incidents=attack_incidents,
    )
