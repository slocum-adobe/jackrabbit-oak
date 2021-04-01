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
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;

/**
 * {@code TreePermission} implementation for all tree located within one of the
 * supported paths which may or may not contain a CUG.
 */
final class CugTreePermission extends AbstractTreePermission implements CugConstants {

    private final TreePermission parent;
    private Status status;

    CugTreePermission(Tree tree, TreeType type, TreePermission parent,
                      ProtectPermissionProvider permissionProvider) {
        super(tree, type, permissionProvider);
        this.parent = parent;
    }

    CugTreePermission(Tree tree, TreeType type, TreePermission parent,
                      ProtectPermissionProvider permissionProvider, boolean inCug, boolean canRead, boolean hasNestedCug) {
        super(tree, type, permissionProvider);
        this.parent = parent;
        status = new Status(inCug, canRead, hasNestedCug);
    }

    boolean isInCug() {
        if (status == null) {
            loadStatus();
        }
        return status.inCug;
    }

    boolean isAllow() {
        if (status == null) {
            loadStatus();
        }
        return status.allow;
    }
    
    boolean hasNestedCug() {
        if (status == null) {
            loadStatus();
        }
        return status.hasNested;
    }
    
    private Status getStatus() {
        if (status == null) {
            loadStatus();
        }
        return status;
    }
    
    private void loadStatus() {
        CugTreePermission parentCugPerm = (parent instanceof CugTreePermission) ? (CugTreePermission) parent : null;
        // need to load information
        Tree cugTree = CugUtil.getCug(tree);
        if (cugTree != null) {
            status = new Status(true, permissionProvider.isAllow(cugTree), false);
        } else if (parentCugPerm != null) {
            status = parentCugPerm.getStatus();
        } else {
            status = Status.FALSE;
        }
    }

    private static boolean neverNested(CugTreePermission parentCugPerm) {
        if (parentCugPerm != null) {
            Status st = parentCugPerm.status;
            return st != null && st.inCug && !st.hasNested;
        }
        return false;
    }

    //-----------------------------------------------------< TreePermission >---

    @Override
    public boolean canRead() {
        return isAllow();
    }

    @Override
    public boolean canRead(PropertyState property) {
        return isAllow();
    }

    @Override
    public boolean canReadAll() {
        return false;
    }

    @Override
    public boolean canReadProperties() {
        return isAllow();
    }

    @Override
    public boolean isGranted(long permissions) {
        return permissions == Permissions.READ_NODE && isAllow();
    }

    @Override
    public boolean isGranted(long permissions, PropertyState property) {
        return permissions == Permissions.READ_PROPERTY && isAllow();
    }

    //--------------------------------------------------------------------------
    private static final class Status {

        private static final Status FALSE = new Status(false, false, false);

        private final boolean inCug;
        private final boolean allow;
        private final boolean hasNested;

        private Status(boolean inCug, boolean allow, boolean hasNested) {
            this.inCug = inCug;
            this.allow = allow;
            this.hasNested = hasNested;
        }
    }
}