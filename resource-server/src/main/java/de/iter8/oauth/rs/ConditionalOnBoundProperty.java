package de.iter8.oauth.rs;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Conditional;

/**
 * Matches on the value a property <em>binds</em> to, rather than on the characters it was written with.
 *
 * <p>{@code @ConditionalOnProperty} compares the configured value to {@code havingValue} as a string, but
 * configuration is not read that way anywhere else: the binder behind {@code @ConfigurationProperties}
 * accepts {@code on}, {@code yes} and {@code 1} for a boolean, and any mix of case, hyphens and underscores
 * for an enum constant. Every one of those spellings binds to a value while matching no exact string, so a
 * property can read as set and still leave the beans that depend on it out of the context. With
 * {@code iter8.resource-server.enabled=on}, for example, the property binds to {@code true} while matching
 * neither {@code "true"} nor {@code "false"}, so neither security chain would be created.
 *
 * <p>This binds the property the same way the rest of the configuration is bound and compares the result, so
 * whatever spelling an operator uses means here what it means everywhere else.
 *
 * @see OnBoundPropertyCondition
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Repeatable(ConditionalOnBoundProperties.class)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(OnBoundPropertyCondition.class)
@interface ConditionalOnBoundProperty {

    /**
     * @return the full name of the property to bind
     */
    String name();

    /**
     * @return the value to match, written canonically: {@code true}, {@code false}, or an enum constant in
     * kebab-case
     */
    String havingValue();

    /**
     * @return whether to match when the property is not set at all
     */
    boolean matchIfMissing() default false;
}
