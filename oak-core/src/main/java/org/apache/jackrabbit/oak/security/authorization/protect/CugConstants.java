/*************************************************************************
 *
 * ADOBE CONFIDENTIAL
 * ___________________
 *
 *  Copyright 2017 Adobe Systems Incorporated
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Adobe Systems Incorporated and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Adobe Systems Incorporated and its
 * suppliers and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Adobe Systems Incorporated.
 **************************************************************************/
package org.apache.jackrabbit.oak.security.authorization.protect;

/**
 * Constants for the Closed User Group (CUG) feature.
 */
interface CugConstants {

    /**
     * The name of the mixin type that defines the CUG policy node.
     */
    String MIX_REP_CUG_MIXIN = "rep:CugMixin";

    /**
     * The primary node type name of the CUG policy node.
     */
    String NT_REP_CUG_POLICY = "rep:CugPolicy";

    /**
     * The name of the CUG policy node.
     */
    String REP_CUG_POLICY = "rep:cugPolicy";

    /**
     * The name of the hidden property that stores information about nested
     * CUG policy nodes.
     */
    String HIDDEN_NESTED_CUGS = ":nestedCugs";

    /**
     * The name of the hidden property that stores information about the number
     * of CUG roots located close to the root node.
     */
    String HIDDEN_TOP_CUG_CNT = ":topCugCnt";

    /**
     * The name of the property that stores the principal names that are allowed
     * to access the restricted area defined by the CUG (closed user group).
     */
    String REP_PRINCIPAL_NAMES = "rep:principalNames";

    /**
     * Name of the configuration option that specifies the subtrees that allow
     * to define closed user groups.
     *
     * <ul>
     *     <li>Value Type: String</li>
     *     <li>Default: -</li>
     *     <li>Multiple: true</li>
     * </ul>
     */
    String PARAM_CUG_SUPPORTED_PATHS = "cugSupportedPaths";

    /**
     * Name of the configuration option that specifies if CUG content must
     * be respected for permission evaluation.
     *
     * <ul>
     *     <li>Value Type: boolean</li>
     *     <li>Default: false</li>
     *     <li>Multiple: false</li>
     * </ul>
     */
    String PARAM_CUG_ENABLED = "cugEnabled";
}