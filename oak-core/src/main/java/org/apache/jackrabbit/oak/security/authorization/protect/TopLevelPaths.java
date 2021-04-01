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


import com.google.common.collect.Iterables;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.util.Text;

/**
 * Utility class to determine the top-level CUG paths as recorded on the root
 * node.
 */
public class TopLevelPaths implements CugConstants {

    static final long NONE = -1;
    static final long MAX_CNT = 10;

    private final Root root;

   // private Boolean hasAny;
    private Long cnt;
    private String[] paths;

    TopLevelPaths(Root root) {
        this.root = root;
    }

    boolean hasAny() {
    	return true;
//        if (hasAny == null) {
//            Tree rootTree = root.getTree(PathUtils.ROOT_PATH);
//            hasAny = rootTree.hasProperty(HIDDEN_TOP_CUG_CNT) || CugUtil.hasCug(rootTree);
//        }
//        return hasAny;
    }

    boolean contains(String path) {
        if (!hasAny()) {
            return false;
        }
        if (PathUtils.denotesRoot(path)) {
            return true;
        }

        if (cnt == null) {
            Tree rootTree = root.getTree(PathUtils.ROOT_PATH);
            PropertyState hiddenTopCnt = rootTree.getProperty(HIDDEN_TOP_CUG_CNT);
            if (hiddenTopCnt != null) {
                cnt = hiddenTopCnt.getValue(Type.LONG);
                if (cnt <= MAX_CNT) {
                    PropertyState hidden = root.getTree(PathUtils.ROOT_PATH).getProperty(HIDDEN_NESTED_CUGS);
                    paths = (hidden == null) ? new String[0] : Iterables.toArray(hidden.getValue(Type.STRINGS), String.class);
                } else {
                    paths = null;
                }
            } else {
                cnt = NONE;
            }
        }

        if (cnt == NONE) {
            return false;
        } if (cnt > MAX_CNT) {
            return true;
        } else if (paths != null) {
            for (String p : paths) {
                if (Text.isDescendantOrEqual(path, p)) {
                    return true;
                }
            }
        }
        return false;
    }
}