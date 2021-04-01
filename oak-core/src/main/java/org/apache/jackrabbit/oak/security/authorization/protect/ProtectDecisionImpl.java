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
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.jackrabbit.oak.api.Tree;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import adobe.protect.core.secure.access.api.ProtectOverrideRule;
import adobe.protect.core.secure.access.api.ProtectRule;
import adobe.protect.core.secure.auth.impl.ProtectPrincipal;

public class ProtectDecisionImpl {

	protected static final Logger log = LoggerFactory.getLogger(ProtectDecisionImpl.class);
	    
	public static boolean evaluate(Tree cugTree, Set<Principal> principals, ProtectPrincipal user,Map<String,ProtectOverrideRule> protectOverrideRuleServices,Map<String,ProtectRule> protectRuleServices){
		if(performOverrideRulesEvaluation(cugTree, principals, user, protectOverrideRuleServices)){
			return true;
		}
		
		return performRulesEvaluation(cugTree, principals, user, protectRuleServices);
    }
	
	public static boolean performRulesEvaluation(Tree cugTree, Set<Principal> principals, ProtectPrincipal user,Map<String,ProtectRule> protectRuleServices){
		// No rules = no custom protections. This is the default.
		if(protectRuleServices.isEmpty()){
			return true;
		} else {			
			Boolean evaluateResult = false;
			if(user == null){
				return false;
			}
			//TODO: cache result using ehCache.
			Collection<ProtectRule> d = protectRuleServices.values();
			
			Iterator<ProtectRule> it = d.iterator();
		    while (it.hasNext()) {
		        ProtectRule pr = it.next();
		        try {
					evaluateResult = pr.evaluate(cugTree, principals, user);

					if(!evaluateResult){
						return false;
					}
				} catch (Exception e) {
					log.debug("Protect Control exception",e);
					return false; //Assume if there is an error, that the user does not get access.
				}	
		    }
		}
		return true;
	}
	
	public static boolean performOverrideRulesEvaluation(Tree cugTree, Set<Principal> principals, ProtectPrincipal user,Map<String,ProtectOverrideRule> protectRuleServices){
		// No rules = no custom protections. This is the default.
		if(protectRuleServices.isEmpty()){
			return false;
		} else {			
			Boolean evaluateResult = false;
			
			//TODO: cache result using ehCache.
			Collection<ProtectOverrideRule> d = protectRuleServices.values();
			
			Iterator<ProtectOverrideRule> it = d.iterator();
		    while (it.hasNext()) {
		    	ProtectOverrideRule pr = it.next();
		        try {
					evaluateResult = pr.evaluate(cugTree, principals, user);

					if(evaluateResult){
						return true;
					}
				} catch (Exception e) {
					log.debug("Protect Override Control exception",e);
					return false; //Assume if there is an error, that the user does not get access.
				}	
		    }
		}
		return false;
	}
	
 }