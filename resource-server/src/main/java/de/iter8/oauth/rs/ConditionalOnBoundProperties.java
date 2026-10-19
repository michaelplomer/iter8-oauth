package de.iter8.oauth.rs;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Conditional;

/**
 * Holds repeated {@link ConditionalOnBoundProperty} declarations, all of which must match.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(OnBoundPropertyCondition.class)
@interface ConditionalOnBoundProperties {

    /**
     * @return the conditions that must all match
     */
    ConditionalOnBoundProperty[] value();
}
