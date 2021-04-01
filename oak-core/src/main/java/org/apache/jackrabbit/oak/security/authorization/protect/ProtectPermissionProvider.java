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

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.commons.PathUtils;
//import org.apache.jackrabbit.oak.plugins.tree.factories.RootFactory;
//import org.apache.jackrabbit.oak.plugins.tree.factories.TreeFactory;
import org.apache.jackrabbit.oak.plugins.tree.RootProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeLocation;
import org.apache.jackrabbit.oak.plugins.tree.TreeProvider;
import org.apache.jackrabbit.oak.plugins.tree.TreeType;
import org.apache.jackrabbit.oak.plugins.tree.TreeTypeProvider;
import org.apache.jackrabbit.oak.spi.security.Context;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.AggregatedPermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.RepositoryPermission;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.TreePermission;
import org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.SystemPrincipal;
import org.apache.jackrabbit.oak.spi.security.principal.SystemUserPrincipal;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStateUtils;
import org.osgi.service.component.annotations.Reference;
//import org.apache.jackrabbit.oak.util.TreeUtil;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.plugins.tree.impl.RootProviderService;
import org.apache.jackrabbit.oak.plugins.tree.impl.TreeProviderService;
import org.apache.jackrabbit.oak.security.authorization.ProviderCtx;
import org.apache.jackrabbit.oak.security.authorization.permission.PermissionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import adobe.protect.core.secure.auth.impl.ProtectPrincipal;
import adobe.protect.core.secure.access.api.ProtectOverrideRule;
import adobe.protect.core.secure.access.api.ProtectRule;
import com.google.common.collect.ImmutableSet;


import org.jetbrains.annotations.NotNull;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

// SOURCE: https://jackrabbit.apache.org/oak/docs/apidocs/org/apache/jackrabbit/oak/spi/security/authorization/permission/PermissionProvider.html
// See also: https://jar-download.com/artifacts/org.apache.jackrabbit/oak-security-spi/1.10.2/source-code/org/apache/jackrabbit/oak/spi/security/authorization/permission/PermissionProvider.java

// Main entry point for permission evaluation in Oak. This provider covers permission 
// validation upon read and write access on the Oak API as well as the various permission 
// related methods defined by the JCR API, namely on AccessControlManager and Session.
public class ProtectPermissionProvider implements PermissionProvider, AggregatedPermissionProvider, CugConstants {
	protected static final Logger log = LoggerFactory.getLogger("adobe.protect");
	 private static final Set<String> READ_PRIVILEGE_NAMES = ImmutableSet.of(
	            PrivilegeConstants.JCR_READ,
	            PrivilegeConstants.REP_READ_NODES,
	            PrivilegeConstants.REP_READ_PROPERTIES
	    );

	    private final Root root;
	    private final String[] principalNames;

	    private final TreeTypeProvider typeProvider;
	    private final Context ctx;

	    private final SupportedPaths supportedPaths;
	    private Set<Principal> principals;
	    private ProtectPrincipal user;
	    private Root immutableRoot;
	    private TopLevelPaths topPaths;
//	    TreeProviderService tps; 
//		
//		RootProviderService rps; 
	    private final ProviderCtx providerCtx;
	    
	    private Map<String,ProtectRule> protectRuleServices;
	    private Map<String,ProtectOverrideRule> protectOverrideRuleServices;
	    String PARAM_ADMINISTRATIVE_PRINCIPALS = "administrativePrincipals";
	    
	    public ProtectPermissionProvider(@NotNull Root root,
	                          @NotNull String workspaceName,
	                          @NotNull Set<Principal> principals,
	                          Map<String,ProtectOverrideRule> _protectOverrideRuleServices,
	                          Map<String,ProtectRule> _protectRuleServices,
	                          @NotNull Set<String> supportedPaths,
	                          @NotNull Context ctx,
//	                          @Nonnull TreeProviderService tps, 
//	                          @Nonnull RootProviderService rps)
	                          @NotNull ProviderCtx providerCtx) {
	                          
	        this.root = root;
//	        this.tps = tps; 
//	        this.rps = rps; 
	        this.providerCtx = providerCtx;
	        this.protectRuleServices = _protectRuleServices;
	        this.protectOverrideRuleServices = _protectOverrideRuleServices;
	        immutableRoot = providerCtx.getRootProvider().createReadOnlyRoot(root);
	        principalNames = new String[principals.size()];
	        int i = 0;
	        for (Principal p : principals) {
	            principalNames[i++] = p.getName();
	        }

	        this.principals = principals;
	        
	        for (Principal principal : principals) {
				if(principal instanceof ProtectPrincipal){				
					this.user = (ProtectPrincipal)principal;
					log.debug("PROTECT PRINCIPAL: " + this.user.getName());
				}
			}
	        this.supportedPaths = new SupportedPaths(supportedPaths);
	        this.typeProvider = new TreeTypeProvider(ctx);
	        this.ctx = ctx;

	        topPaths = new TopLevelPaths(immutableRoot);
	    }

		@NotNull
	    TreePermission getTreePermission(@NotNull Tree parent, @NotNull TreeType parentType, @NotNull String childName, @NotNull NodeState childState, @NotNull AbstractTreePermission parentPermission) {
	        Tree t = providerCtx.getTreeProvider().createReadOnlyTree(parent, childName, childState);
	        TreeType type = typeProvider.getType(t, parentType);
	        return getTreePermission(t, type, parentPermission);
			
		}

	    boolean isAllow(@NotNull Tree cugTree) {
	    	try {
	            if (principals != null) {
	            	// Check child node for jcr:content and having protect:mixin. Especially in the cases of pages and assets,
	            	// the mix-in will naturally be on this node.
	            	if(cugTree.hasChild("jcr:content") && CugUtil.hasCug(cugTree)){
	            		return ProtectDecisionImpl.evaluate(cugTree.getChild("jcr:content"), principals, user, this.protectOverrideRuleServices,this.protectRuleServices);
	            	} else {	            	
	            		return ProtectDecisionImpl.evaluate(cugTree, principals, user, this.protectOverrideRuleServices,this.protectRuleServices);
	            	}
            	}
	        }
	        catch (Exception e) {
	            log.trace("{$tree?.path} Caught exception", e);
	        }
	        log.debug("{$tree?.path} - DENYING");	        
	        return false;
	    }
	   
	    //-------------------------------------------------< PermissionProvider >---
	    @Override
	    public void refresh() {
	        immutableRoot = providerCtx.getRootProvider().createReadOnlyRoot(root);	        
	        topPaths = new TopLevelPaths(immutableRoot);
	    }

	    @NotNull
	    @Override
	    public Set<String> getPrivileges(Tree tree) {
	        if (tree != null && canRead(tree)) {
	            return READ_PRIVILEGE_NAMES;
	        } else {
	            return Collections.emptySet();
	        }
	    }

	    @Override
	    public boolean hasPrivileges(Tree tree, @NotNull String... privilegeNames) {
	        if (tree == null) {
	            return false;
	        }
	        for (String privilegeName : privilegeNames) {
	            if (!READ_PRIVILEGE_NAMES.contains(privilegeName)) {
	                return false;
	            }
	        }
	        return canRead(tree);
	    }

	    @NotNull
	    @Override
	    public RepositoryPermission getRepositoryPermission() {
	        return RepositoryPermission.EMPTY;
	    }

	    @NotNull
	    @Override
	    public TreePermission getTreePermission(@NotNull Tree tree, @NotNull TreePermission parentPermission) {
	        if (TreePermission.NO_RECOURSE == parentPermission) {
	            throw new IllegalStateException("Attempt to create tree permission for path '"+ tree.getPath() +"', which is either not supported or doesn't contain any CUGs.");
	        }
	        Tree immutableTree = getImmutableTree(tree);
	        TreeType type = typeProvider.getType(immutableTree);
	        return getTreePermission(immutableTree, type, parentPermission);
	    }

	    @Override
	    public boolean isGranted(@NotNull Tree tree, PropertyState property, long permissions) {
	        if (isRead(permissions)) {
	            return canRead(tree);
	        } else {
	            return false;
	        }
	    }

	    @Override
	    public boolean isGranted(@NotNull String oakPath, @NotNull String jcrActions) {
	        TreeLocation location = TreeLocation.create(immutableRoot, oakPath);
	        if (ctx.definesLocation(location) || NodeStateUtils.isHiddenPath(oakPath)) {
	            return false;
	        }

	        long permissions = Permissions.getPermissions(jcrActions, location, false);
	        return isGranted(location, permissions);
	    }

	    //---------------------------------------< AggregatedPermissionProvider >---
	    @NotNull
	    @Override
	    public PrivilegeBits supportedPrivileges(Tree tree, PrivilegeBits privilegeBits) {
	        if (tree == null) {
	            return PrivilegeBits.EMPTY;
	        }

	        PrivilegeBits pb;
	        if (privilegeBits == null) {
	            pb = PrivilegeBits.BUILT_IN.get(PrivilegeConstants.JCR_READ);
	        } else {
	            pb = PrivilegeBits.getInstance(privilegeBits);
	            pb.retain(PrivilegeBits.BUILT_IN.get(PrivilegeConstants.JCR_READ));
	        }

	        if (pb.isEmpty() || !includesCug(tree)) {
	            return PrivilegeBits.EMPTY;
	        } else {
	            return pb;
	        }
	    }

	    @Override
	    public long supportedPermissions(Tree tree, PropertyState property, long permissions) {
	        if (tree == null) {
	            // repository level permissions are not supported
	            return Permissions.NO_PERMISSION;
	        }

	        long supported = permissions & Permissions.READ;
	        if (supported != Permissions.NO_PERMISSION && includesCug(tree)) {
	            return supported;
	        } else {
	            return Permissions.NO_PERMISSION;
	        }
	    }

	    @Override
	    public long supportedPermissions(@NotNull TreeLocation location, long permissions) {
	        long supported = permissions & Permissions.READ;
	        if (supported != Permissions.NO_PERMISSION && includesCug(getTreeFromLocation(location))) {
	            return supported;
	        } else {
	            return Permissions.NO_PERMISSION;
	        }
	    }

	    @Override
	    public long supportedPermissions(@NotNull TreePermission treePermission, PropertyState property, long permissions) {
	        long supported = permissions & Permissions.READ;
	        if (supported != Permissions.NO_PERMISSION && (treePermission instanceof CugTreePermission) && ((CugTreePermission) treePermission).isInCug()) {
	            return supported;
	        } else {
	            return Permissions.NO_PERMISSION;
	        }
	    }

	    @Override
	    public boolean isGranted(@NotNull TreeLocation location, long permissions) {
	        if (isRead(permissions)) {
	            Tree tree = getTreeFromLocation(location);
	            if (tree != null) {
	                return isGranted(tree, location.getProperty(), permissions);
	            }
	        }
	        return false;
	    }

	    @NotNull
	    public TreePermission getTreePermission(@NotNull Tree immutableTree, @NotNull TreeType type, @NotNull TreePermission parentPermission) {
	        TreePermission tp;
	        boolean parentIsCugPermission = (parentPermission instanceof CugTreePermission);
            if (parentIsCugPermission) {
                tp = new CugTreePermission(immutableTree, type, parentPermission, this);
            } else {
                String path = immutableTree.getPath();
                if (includes(path)) {
                	tp = new CugTreePermission(immutableTree, type, parentPermission, this);
                }
                else if (mayContain(path) || isJcrSystemPath(immutableTree)) {
                    tp =  new EmptyCugTreePermission(immutableTree, type, this);
                } else {
                    tp = TreePermission.NO_RECOURSE;
                }
            }
	        return tp;
	    }

	    //--------------------------------------------------------------------------

	    private static boolean isJcrSystemPath(@NotNull Tree tree) {
	        return JcrConstants.JCR_SYSTEM.equals(tree.getName());
	    }

	    private static boolean isRead(long permission) {
	        return permission == Permissions.READ_NODE || permission == Permissions.READ_PROPERTY || permission == Permissions.READ;
	    }

	    private static boolean isSupportedType(@NotNull TreeType type) {
	        return type == TreeType.DEFAULT;
	    }

	    private boolean includesCug(Tree tree) {
	        if (tree != null) {
	            Tree immutableTree = getImmutableTree(tree);
	            TreeType type = typeProvider.getType(immutableTree);
	            if (isSupportedType(type) && topPaths.hasAny()) {
	                return getCugRoot(immutableTree, type) != null;
	            }
	        }
	        return false;
	    }

	    private boolean includes(@NotNull String path) {
	        return supportedPaths.includes(path);
	    }

	    private boolean mayContain(@NotNull String path) {
	        return supportedPaths.mayContainCug(path) && topPaths.contains(path);
	    }

	    /**
	     * Returns the {@code tree} that holds a CUG policy in the ancestry of the
	     * given {@code tree} with the specified {@code path} or {@code null} if no
	     * such tree exists and thus no CUG is effective at the specified path.
	     *
	     * @param immutableTree The target tree.
	     * @param type the type of this tree.
	     * @return the {@code tree} holding the CUG policy that effects the specified
	     * path or {@code null} if no such policy exists.
	     */
	    private Tree getCugRoot(@NotNull Tree immutableTree, @NotNull TreeType type) {
	        Tree tree = immutableTree;
	        String p = immutableTree.getPath();	        
	        if (!includes(p)) {
	            return null;
	        }
	        if (CugUtil.hasCug(tree)) {
	            return tree;
	        }
	        String parentPath;
	        while (!tree.isRoot()) {
	            parentPath = PathUtils.getParentPath(p);
	            if (!includes(parentPath)) {
	                break;
	            }
	            tree = tree.getParent();
	            if (CugUtil.hasCug(tree)) {
	                return tree;
	            }
	        }
	        return null;
	    }

	    private boolean canRead(@NotNull Tree tree) {
	        Tree immutableTree = getImmutableTree(tree);
	        TreeType type = typeProvider.getType(immutableTree);
	        if (!isSupportedType(type) || !topPaths.hasAny()) {
	            return false;
	        }	        
	        Tree cugRoot = getCugRoot(immutableTree, type);
	        if (cugRoot != null) {
	            Tree cugTree = CugUtil.getCug(cugRoot);
	            if (cugTree != null) {
	                return isAllow(cugTree);
	            }
	        }
	        return false;
	    }

	    @NotNull
	    private Tree getImmutableTree(@NotNull Tree tree) {
	        return TreeUtil.isReadOnlyTree(tree) ? tree : immutableRoot.getTree(tree.getPath());
	    }

	    
	    private static Tree getTreeFromLocation(@NotNull TreeLocation location) {
	        Tree tree = (location.getProperty() == null) ? location.getTree() : location.getParent().getTree();
	        while (tree == null && !PathUtils.denotesRoot(location.getPath())) {
	            location = location.getParent();
	            tree = location.getTree();
	        }
	        return tree;
	    }
	}
