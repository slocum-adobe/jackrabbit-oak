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


import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.state.NodeState;

abstract class AbstractTreePermission implements TreePermission {

    final Tree tree;
    final TreeType type;
    final ProtectPermissionProvider permissionProvider;

    AbstractTreePermission(Tree tree, TreeType type, ProtectPermissionProvider permissionProvider) {
        this.tree = tree;
        this.type = type;
        this.permissionProvider = permissionProvider;
    }

    @Override
    public TreePermission getChildPermission(String childName, NodeState childState) {
        return permissionProvider.getTreePermission(tree, type, childName, childState, this);
    }
}