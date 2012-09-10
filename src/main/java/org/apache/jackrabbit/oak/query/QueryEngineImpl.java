/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.query;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.jackrabbit.mk.api.MicroKernel;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.api.CoreValue;
import org.apache.jackrabbit.oak.api.CoreValueFactory;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.query.index.FilterImpl;
import org.apache.jackrabbit.oak.query.index.TraversingIndex;
import org.apache.jackrabbit.oak.spi.QueryIndex;
import org.apache.jackrabbit.oak.spi.QueryIndexProvider;
import org.apache.jackrabbit.oak.spi.state.NodeStore;

/**
 * The query engine implementation.
 */
public class QueryEngineImpl {

    static final String SQL2 = "JCR-SQL2";
    static final String SQL = "sql";
    static final String XPATH = "xpath";
    static final String JQOM = "JCR-JQOM";

    private final NodeStore store;
    private final MicroKernel mk;
    private final CoreValueFactory vf;
    private final QueryIndexProvider indexProvider;

    public QueryEngineImpl(NodeStore store, MicroKernel mk, QueryIndexProvider indexProvider) {
        this.store = store;
        this.mk = mk;
        this.vf = store.getValueFactory();
        this.indexProvider = indexProvider;
    }

    public List<String> getSupportedQueryLanguages() {
        return Arrays.asList(SQL2, SQL, XPATH, JQOM);
    }

    /**
     * Parse the query (check if it's valid) and get the list of bind variable names.
     *
     * @param statement
     * @param language
     * @return the list of bind variable names
     * @throws ParseException
     */
    public List<String> getBindVariableNames(String statement, String language) throws ParseException {
        Query q = parseQuery(statement, language);
        return q.getBindVariableNames();
    }

    private Query parseQuery(String statement, String language) throws ParseException {
        Query q;
        if (SQL2.equals(language) || JQOM.equals(language)) {
            SQL2Parser parser = new SQL2Parser(vf);
            q = parser.parse(statement);
        } else if (SQL.equals(language)) {
            SQL2Parser parser = new SQL2Parser(vf);
            parser.setSupportSQL1(true);
            q = parser.parse(statement);
        } else if (XPATH.equals(language)) {
            XPathToSQL2Converter converter = new XPathToSQL2Converter();
            String sql2 = converter.convert(statement);
            SQL2Parser parser = new SQL2Parser(vf);
            q = parser.parse(sql2);
        } else {
            throw new ParseException("Unsupported language: " + language, 0);
        }
        return q;
    }

    public ResultImpl executeQuery(String statement, String language, ContentSession session,
            long limit, long offset, Map<String, ? extends CoreValue> bindings,
            NamePathMapper namePathMapper) throws ParseException {
        Query q = parseQuery(statement, language);
        q.setSession(session);
        q.setNamePathMapper(namePathMapper);
        q.setLimit(limit);
        q.setOffset(offset);
        q.setMicroKernel(mk);
        if (bindings != null) {
            for (Entry<String, ? extends CoreValue> e : bindings.entrySet()) {
                q.bindValue(e.getKey(), e.getValue());
            }
        }
        q.setQueryEngine(this);
        q.prepare();
        String revision = mk.getHeadRevision();
        return q.executeQuery(revision, store.getRoot());
    }

    public QueryIndex getBestIndex(FilterImpl filter) {
        QueryIndex best = null;
        double bestCost = Double.MAX_VALUE;
        for (QueryIndex index : getIndexes()) {
            double cost = index.getCost(filter);
            if (cost < bestCost) {
                best = index;
            }
        }
        if (best == null) {
            best = new TraversingIndex();
        }
        return best;
    }

    private List<? extends QueryIndex> getIndexes() {
        return indexProvider.getQueryIndexes(store);
    }

}
