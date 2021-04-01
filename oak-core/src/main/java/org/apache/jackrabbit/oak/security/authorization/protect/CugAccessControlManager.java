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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;

import adobe.protect.core.secure.access.api.CugPolicy;
import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.PolicyOwner;
//import org.apache.jackrabbit.oak.spi.security.authorization.cug.CugPolicy;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AbstractAccessControlManager;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.Permissions;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalConfiguration;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.jackrabbit.oak.plugins.nodetype.NodeTypeConstants.NODE_TYPES_PATH;

/**
 * Implementation of the {@link org.apache.jackrabbit.api.security.JackrabbitAccessControlManager}
 * interface that allows to create, modify and remove closed user group policies.
 */
public class CugAccessControlManager extends AbstractAccessControlManager implements CugConstants, PolicyOwner {

    private static final Logger log = LoggerFactory.getLogger(CugAccessControlManager.class);

    private final ConfigurationParameters config;
    private final PrincipalManager principalManager;

//    public CugAccessControlManager(@Nonnull Root root, @Nonnull NamePathMapper namePathMapper, @Nonnull SecurityProvider securityProvider) {
//        super(root, namePathMapper, securityProvider);
//
//        config = securityProvider.getConfiguration(AuthorizationConfiguration.class).getParameters();
//        principalManager = securityProvider.getConfiguration(PrincipalConfiguration.class).getPrincipalManager(root, namePathMapper);
//    }

    public CugAccessControlManager(Root root, NamePathMapper namePathMapper, SecurityProvider securityProvider) {
    	super(root, namePathMapper, securityProvider);
    	if(securityProvider != null){
        	config = securityProvider.getConfiguration(AuthorizationConfiguration.class).getParameters();
        	principalManager = securityProvider.getConfiguration(PrincipalConfiguration.class).getPrincipalManager(root, namePathMapper);
    	} else {
    		config = null;
    		principalManager = null;
    	}
        //config = securityProvider.getConfiguration(AuthorizationConfiguration.class).getParameters();
        //principalManager = securityProvider.getConfiguration(PrincipalConfiguration.class).getPrincipalManager(root, namePathMapper);
    }
    //-----------------------------------------------< AccessControlManager >---

    @Override
    public Privilege[] getSupportedPrivileges(String absPath) throws RepositoryException {
//        if (isSupportedPath(getOakPath(absPath))) {
//            return new Privilege[] {privilegeFromName(PrivilegeConstants.JCR_READ)};
//        } else {
            return new Privilege[0];
//        }
    }

    @Override
    public AccessControlPolicy[] getPolicies(String absPath) throws RepositoryException {
//        String oakPath = getOakPath(absPath);
//        if (oakPath != null && isSupportedPath(oakPath)) {
//            CugPolicy cug = getCugPolicy(oakPath);
//            if (cug != null) {
//                return new AccessControlPolicy[]{cug};
//            }
//        }
        return new AccessControlPolicy[0];
    }

    @Override
    public AccessControlPolicy[] getEffectivePolicies(String absPath) throws RepositoryException {
//        String oakPath = getOakPath(absPath);
//        getTree(oakPath, Permissions.READ_ACCESS_CONTROL, true);
//
//        boolean enabled = config.getConfigValue(CugConstants.PARAM_CUG_ENABLED, false);
//        if (enabled) {
//            Root r = getRoot().getContentSession().getLatestRoot();
//            List<AccessControlPolicy> effective = new ArrayList<AccessControlPolicy>();
//            while (oakPath != null) {
//                if (isSupportedPath(oakPath)) {
//                    CugPolicy cug = getCugPolicy(oakPath, r.getTree(oakPath));
//                    if (cug != null) {
//                        effective.add(cug);
//                    }
//                }
//                oakPath = (PathUtils.denotesRoot(oakPath)) ? null : PathUtils.getAncestorPath(oakPath, 1);
//            }
//            return effective.toArray(new AccessControlPolicy[effective.size()]);
//        } else {
            return new AccessControlPolicy[0];
        //}
    }

    @Override
    public AccessControlPolicyIterator getApplicablePolicies(String absPath) throws RepositoryException {
//        String oakPath = getOakPath(absPath);
//        if (oakPath == null || !isSupportedPath(oakPath)) {
            return AccessControlPolicyIteratorAdapter.EMPTY;
//        } else {
//            CugPolicy cug = getCugPolicy(oakPath);
//            if (cug == null) {
//                cug = new CugPolicyImpl(oakPath, getNamePathMapper(), principalManager, CugUtil.getImportBehavior(config));
//                return new AccessControlPolicyIteratorAdapter(ImmutableSet.of(cug));
//            } else {
//                return AccessControlPolicyIteratorAdapter.EMPTY;
//            }
//        }
    }

    @Override
    public void removePolicy(String absPath, AccessControlPolicy policy) throws RepositoryException {
//        String oakPath = getOakPath(absPath);
//        if (isSupportedPath(oakPath)) {
//            checkValidPolicy(absPath, policy);
//
//            Tree tree = getTree(oakPath, Permissions.MODIFY_ACCESS_CONTROL, true);
//            Tree cug = tree.getChild(REP_CUG_POLICY);
//            if (!CugUtil.definesCug(cug)) {
//                throw new AccessControlException("Unexpected primary type of node rep:cugPolicy.");
//            } else {
//                cug.remove();
//            }
//        } else {
//            throw new AccessControlException("Unsupported path: " + absPath);
//        }
    }

    @Override
    public void setPolicy(String absPath, AccessControlPolicy policy) throws RepositoryException {
//        String oakPath = getOakPath(absPath);
//        if (isSupportedPath(oakPath)) {
//            checkValidPolicy(absPath, policy);
//
//            Tree tree = getTree(oakPath, Permissions.MODIFY_ACCESS_CONTROL, true);
//            Tree typeRoot = getRoot().getTree(NODE_TYPES_PATH);
//            if (!TreeUtil.isNodeType(tree, MIX_REP_CUG_MIXIN, typeRoot)) {
//                TreeUtil.addMixin(tree, MIX_REP_CUG_MIXIN, typeRoot, null);
//            }
//            Tree cug;
//            if (tree.hasChild(REP_CUG_POLICY)) {
//                cug = tree.getChild(REP_CUG_POLICY);
//                if (!CugUtil.definesCug(cug)) {
//                    throw new AccessControlException("Unexpected primary type of node rep:cugPolicy.");
//                }
//            } else {
//                cug = TreeUtil.addChild(tree, REP_CUG_POLICY, NT_REP_CUG_POLICY, typeRoot, null);
//            }
//            cug.setProperty(REP_PRINCIPAL_NAMES, ((CugPolicyImpl) policy).getPrincipalNames(), Type.STRINGS);
//        } else {
            throw new AccessControlException("Unsupported path: " + absPath);
//        }
    }

    //-------------------------------------< JackrabbitAccessControlManager >---

    @Override
    public JackrabbitAccessControlPolicy[] getApplicablePolicies(Principal principal) throws RepositoryException {
        // editing by 'principal' is not supported
        return new JackrabbitAccessControlPolicy[0];
    }

    @Override
    public JackrabbitAccessControlPolicy[] getPolicies(Principal principal) throws RepositoryException {
        // editing by 'principal' is not supported
        return new JackrabbitAccessControlPolicy[0];
    }

    @Override
    public AccessControlPolicy[] getEffectivePolicies(Set<Principal> principals) throws RepositoryException {
        // editing by 'principal' is not supported
        return new AccessControlPolicy[0];
    }

    //--------------------------------------------------------< PolicyOwner >---
    @Override
    public boolean defines(String absPath, AccessControlPolicy accessControlPolicy) {
        return isValidPolicy(absPath, accessControlPolicy);
    }

    //--------------------------------------------------------------------------

    private boolean isSupportedPath(String oakPath) throws RepositoryException {
        checkValidPath(oakPath);
        return CugUtil.isSupportedPath(oakPath, config);
    }

    private void checkValidPath(String oakPath) throws RepositoryException {
        if (oakPath != null) {
            getTree(oakPath, Permissions.NO_PERMISSION, false);
        }
    }

    private CugPolicy getCugPolicy(String oakPath) throws RepositoryException {
        return getCugPolicy(oakPath, getTree(oakPath, Permissions.READ_ACCESS_CONTROL, true));
    }

    private CugPolicy getCugPolicy(String oakPath, Tree tree) {
        Tree cug = tree.getChild(REP_CUG_POLICY);
        if (CugUtil.definesCug(cug)) {
            return new CugPolicyImpl(oakPath, getNamePathMapper(), principalManager, CugUtil.getImportBehavior(config), getPrincipals(cug));
        } else {
            return null;
        }
    }

    private Set<Principal> getPrincipals(Tree cugTree) {
        PropertyState property = cugTree.getProperty(REP_PRINCIPAL_NAMES);
        if (property == null) {
            return Collections.emptySet();
        } else {
            return ImmutableSet.copyOf(Iterables.transform(property.getValue(Type.STRINGS), new Function<String, Principal>() {
                @Override
                public Principal apply(String principalName) {
                    Principal principal = principalManager.getPrincipal(principalName);
                    if (principal == null) {
                        log.debug("Unknown principal " + principalName);
                        principal = new PrincipalImpl(principalName);
                    }
                    return principal;
                }
            }));
        }
    }

    private static boolean isValidPolicy(String absPath, AccessControlPolicy policy) {
        return policy instanceof CugPolicyImpl && ((CugPolicyImpl) policy).getPath().equals(absPath);
    }

    private static void checkValidPolicy(String absPath, AccessControlPolicy policy) throws AccessControlException {
        if (!(policy instanceof CugPolicyImpl)) {
            throw new AccessControlException("Unsupported policy implementation: " + policy);
        }

        CugPolicyImpl cug = (CugPolicyImpl) policy;
        if (!cug.getPath().equals(absPath)) {
            throw new AccessControlException("Path mismatch: Expected " + cug.getPath() + ", Found: " + absPath);
        }
    }
}