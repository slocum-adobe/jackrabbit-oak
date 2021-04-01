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

import java.util.ArrayList;
//
//import javax.annotation.CheckForNull;
//import javax.annotation.Nonnull;
//import javax.annotation.Nullable;

import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.state.NodeBuilder;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.xml.ImportBehavior;
import org.apache.jackrabbit.oak.spi.xml.ProtectedItemImporter;
import org.apache.jackrabbit.util.Text;

/**
 * Utility methods for this CUG implementation package.
 */
final class CugUtil implements CugConstants {

    private CugUtil(){}

    public static boolean hasCug(Tree tree) {
        //return tree.exists() && tree.hasChild(REP_CUG_POLICY);
    	return tree.exists() && hasProtectMixin(tree);
    }

    public static boolean hasCug(NodeState state) {
        return state != null && state.hasChildNode(REP_CUG_POLICY);
    }

    public static boolean hasCug(NodeBuilder builder) {
        return builder != null && builder.hasChildNode(REP_CUG_POLICY);
    }

    
    private static boolean hasProtectMixin(Tree tree){
    	ArrayList<String> mixins = null;
        ArrayList<String> childMixins = null;
    	
        try {
        	
        	if(tree.hasChild("jcr:content")){
        		//retrieve current tree node mixins
        		childMixins = getMixins(tree.getChild("jcr:content"), mixins);
            	if(childMixins != null){
            		if(childMixins.contains("mix:protect")){
            			return true;
            		}
            	}    
        	}
        	
        	//retrieve current tree node mixins
        	mixins = getMixins(tree, mixins);
        	if(mixins != null){
        		if(mixins.contains("mix:protect")){
        			return true;
        		}
        	}        	
        }
        catch (Exception e) {
        	//log.error(tree.getPath() + " " + cacUser.getName() + " Caught Exception retrieving jcr:content mixins property - DENYING", e);
            return false;
        }
        return false;
    }
    
    private static ArrayList<String> getMixins(Tree tree, ArrayList<String> mixins) {
		if(tree != null){
			PropertyState mixinsProperty = tree.getProperty(JcrConstants.JCR_MIXINTYPES);
		    if (mixinsProperty != null) {
		    	mixins = (ArrayList<String>) mixinsProperty.getValue(mixinsProperty.getType());
		    }
		}
		return mixins;
	}
    
    public static Tree getCug(Tree tree) {
        Tree cugTree = (CugUtil.hasCug(tree)) ? tree : null;
        if (cugTree != null) {
            return cugTree;
        } else {
            return null;
        }
    }

    public static boolean definesCug(Tree tree) {
      return tree.exists();

//        return tree.exists() && REP_CUG_POLICY.equals(tree.getName()) && NT_REP_CUG_POLICY.equals(TreeUtil.getPrimaryTypeName(tree));
    }
//
//    public static boolean definesCug(@Nonnull String name, @Nonnull NodeState state) {
//        return REP_CUG_POLICY.equals(name) && NT_REP_CUG_POLICY.equals(NodeStateUtils.getPrimaryTypeName(state));
//    }
//
//    public static boolean definesCug(@Nonnull Tree tree, @Nonnull PropertyState property) {
//        return REP_PRINCIPAL_NAMES.equals(property.getName()) && definesCug(tree);
//    }
//
//    public static boolean hasNestedCug(@Nonnull Tree cugTree) {
//        return cugTree.hasProperty(CugConstants.HIDDEN_NESTED_CUGS);
//    }

    public static boolean isSupportedPath(String oakPath, ConfigurationParameters config) {
        if (oakPath == null) {
            return false;
        } else {
//            for (String supportedPath : config.getConfigValue(ProtectAuthorizationConfigurationImpl.PARAM_CUG_SUPPORTED_PATHS, new String[0])) {
//                if (Text.isDescendantOrEqual(supportedPath, oakPath)) {
//                    return true;
//                }
//            }
        }
        return false;
    }

    public static int getImportBehavior(ConfigurationParameters config) {
        String importBehaviorStr = config.getConfigValue(ProtectedItemImporter.PARAM_IMPORT_BEHAVIOR, ImportBehavior.NAME_ABORT);
        return ImportBehavior.valueFromString(importBehaviorStr);
    }
}