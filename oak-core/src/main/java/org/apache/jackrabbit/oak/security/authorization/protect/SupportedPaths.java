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

import java.util.Set;

import org.apache.jackrabbit.oak.commons.PathUtils;

public class SupportedPaths {

    private final String[] supportedPaths;
    private final String[] supportedAltPaths;

    private final boolean includesRootPath;

    SupportedPaths(Set<String> supportedPaths) {
        this.supportedPaths = supportedPaths.toArray(new String[supportedPaths.size()]);
        supportedAltPaths = new String[supportedPaths.size()];

        boolean foundRootPath = false;
        int i = 0;
        for (String p : supportedPaths) {
            if (PathUtils.denotesRoot(p)) {
                foundRootPath = true;
            } else {
                supportedAltPaths[i++] = p + '/';
            }
        }
        includesRootPath = foundRootPath;
    }

    /**
     * Test if the specified {@code path} is contained in any of the configured
     * supported paths for CUGs.
     *
     * @param path An absolute path.
     * @return {@code true} if the specified {@code path} is equal to or a
     * descendant of one of the configured supported paths.
     */
    boolean includes(String path) {
        if (supportedPaths.length == 0) {
            return false;
        }
        if (includesRootPath) {
            return true;
        }
        for (String p : supportedAltPaths) {
            if (path.startsWith(p)) {
                return true;
            }
        }
        for (String p : supportedPaths) {
            if (path.equals(p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests if further evaluation below {@code path} is required as one of the
     * configured supported paths is a descendant (e.g. there might be CUGs
     * in the subtree although the specified {@code path} does not directly
     * support CUGs.
     *
     * @param path An absolute path
     * @return {@code true} if there exists a configured supported path that is
     * a descendant of the given {@code path}.
     */
    boolean mayContainCug(String path) {
        if (supportedPaths.length == 0) {
            return false;
        }
        if (includesRootPath || PathUtils.denotesRoot(path)) {
            return true;
        }
        String path2 = path + '/';
        for (String sp : supportedPaths) {
            if (sp.startsWith(path2)) {
                return true;
            }
        }
        return false;
    }
}