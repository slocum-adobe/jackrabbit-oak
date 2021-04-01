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


import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;

/**
 * Same as {@link org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission#EMPTY}
 * from a permission point of view but indicating that it refers to a tree that
 * potentially contains a CUG in the subtree thus forcing continued evaluation,
 * where as {@link org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission#EMPTY}
 * indicates that this permission model will never grant access in the subtree
 * and thus can be ignored.
 */
public final class EmptyCugTreePermission extends AbstractTreePermission {

    EmptyCugTreePermission(Tree tree, TreeType type, ProtectPermissionProvider permissionProvider) {
        super(tree, type, permissionProvider);
    }

    //-----------------------------------------------------< TreePermission >---

    @Override
    public boolean canRead() {
        return false;
    }

    @Override
    public boolean canRead(PropertyState property) {
        return false;
    }

    @Override
    public boolean canReadAll() {
        return false;
    }

    @Override
    public boolean canReadProperties() {
        return false;
    }

    @Override
    public boolean isGranted(long permissions) {
        return false;
    }

    @Override
    public boolean isGranted(long permissions, PropertyState property) {
        return false;
    }
}