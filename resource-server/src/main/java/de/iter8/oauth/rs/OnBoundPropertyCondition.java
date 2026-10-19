package de.iter8.oauth.rs;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * The condition behind {@link ConditionalOnBoundProperty}.
 *
 * <p>A required value of {@code true} or {@code false} is compared after binding to {@code Boolean}, which
 * is what makes {@code on}, {@code yes} and {@code 1} mean what they mean everywhere else. Anything else is
 * compared after stripping case, hyphens and underscores from both sides, which is the same latitude Spring
 * allows when binding a string to an enum constant.
 */
final class OnBoundPropertyCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Binder binder = Binder.get(context.getEnvironment());
        for (Map<String, Object> attributes : declarations(metadata)) {
            ConditionOutcome outcome = evaluate(binder, attributes);
            if (!outcome.isMatch()) {
                return outcome;
            }
        }
        return ConditionOutcome.match();
    }

    /**
     * Collects the declarations to evaluate. A single use appears under its own type; repeated uses are
     * wrapped by the compiler into the container, and only one of the two is ever present.
     */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> declarations(AnnotatedTypeMetadata metadata) {
        List<Map<String, Object>> declarations = new ArrayList<>();
        Map<String, Object> single =
                metadata.getAnnotationAttributes(ConditionalOnBoundProperty.class.getName());
        if (single != null) {
            declarations.add(single);
        }
        Map<String, Object> repeated =
                metadata.getAnnotationAttributes(ConditionalOnBoundProperties.class.getName());
        if (repeated != null) {
            for (Object nested : (Object[]) repeated.get("value")) {
                declarations.add((Map<String, Object>) nested);
            }
        }
        return declarations;
    }

    private ConditionOutcome evaluate(Binder binder, Map<String, Object> attributes) {
        String name = (String) attributes.get("name");
        String required = (String) attributes.get("havingValue");
        boolean matchIfMissing = (Boolean) attributes.get("matchIfMissing");

        ConditionMessage.Builder message = ConditionMessage
                .forCondition(ConditionalOnBoundProperty.class, "(" + name + "=" + required + ")");

        // Binding failures are left to propagate. The same value is about to be bound into a
        // @ConfigurationProperties record anyway, and a report of "condition did not match" would hide a
        // value that is not merely spelled unusually but wrong.
        if (isBoolean(required)) {
            Boolean bound = binder.bind(name, Boolean.class).orElse(null);
            if (bound == null) {
                return new ConditionOutcome(matchIfMissing, message.because("the property is not set"));
            }
            return new ConditionOutcome(bound == Boolean.parseBoolean(required),
                    message.because("it binds to " + bound));
        }

        String bound = binder.bind(name, String.class).orElse(null);
        if (bound == null) {
            return new ConditionOutcome(matchIfMissing, message.because("the property is not set"));
        }
        return new ConditionOutcome(canonical(bound).equals(canonical(required)),
                message.because("it is set to '" + bound + "'"));
    }

    private static boolean isBoolean(String required) {
        return "true".equalsIgnoreCase(required) || "false".equalsIgnoreCase(required);
    }

    /**
     * Reduces a value to what Spring compares when binding one to an enum constant: case, hyphens and
     * underscores carry no meaning.
     */
    private static String canonical(String value) {
        return value.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
    }
}
