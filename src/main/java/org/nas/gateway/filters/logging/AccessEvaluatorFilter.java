package org.nas.gateway.filters.logging;

import org.slf4j.MDC;

import ch.qos.logback.core.boolex.EvaluationException;
import ch.qos.logback.core.boolex.EventEvaluator;
import ch.qos.logback.core.filter.AbstractMatcherFilter;
import ch.qos.logback.core.spi.FilterReply;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessEvaluatorFilter<E> extends AbstractMatcherFilter<E> {
    EventEvaluator<E> evaluator;

    @Override
    public void start() {
        if (evaluator != null) {
            super.start();
        } else {
            addError("No evaluator set for filter " + this.getName());
        }
    }

    public FilterReply decide(E event) {
        if(!isStarted() || !evaluator.isStarted()) {
            return FilterReply.NEUTRAL;
        }

        try {
            if (evaluator.evaluate(event)){
                return onMatch;
            } else {
                return onMismatch;
            }
        } catch (EvaluationException e) {
            addError(evaluator.getName() + " threw exception: " + e.getMessage());
            return FilterReply.NEUTRAL;
        } finally {
            MDC.clear();
        }
    }
}
