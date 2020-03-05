/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.db.sql;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordPassiveScan;
import org.parosproxy.paros.db.TablePassiveScan;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SqlTablePassiveScan extends SqlAbstractTable implements TablePassiveScan {

    private static final String SCANID = DbSQL.getSQL("passivescan.field.scanid");
    private static final String SCANNAME = DbSQL.getSQL("passivescan.field.scanname");
    private static final String SCANTIME = DbSQL.getSQL("passivescan.field.scantime");

    public SqlTablePassiveScan() {}

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {}

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TablePassiveScan#getLatestPassiveScan()
     */
    @Override
    public synchronized RecordPassiveScan getLatestPassiveScan() throws DatabaseException {
        SqlPreparedStatementWrapper psGetLatestPassiveScan = null;
        try {
            psGetLatestPassiveScan = DbSQL.getSingleton().getPreparedStatement("passivescan.ps.getlatestpassivescan");
            try (ResultSet rs = psGetLatestPassiveScan.getPs().executeQuery()) {
                return build(rs);
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        } finally {
            DbSQL.getSingleton().releasePreparedStatement(psGetLatestPassiveScan);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TablePassiveScan#read(int)
     */
    @Override
    public synchronized RecordPassiveScan read(int scanId) throws DatabaseException {
        SqlPreparedStatementWrapper psRead = null;
        try {
            psRead = DbSQL.getSingleton().getPreparedStatement("passivescan.ps.read");
            psRead.getPs().setInt(1, scanId);

            try (ResultSet rs = psRead.getPs().executeQuery()) {
                return build(rs);
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        } finally {
            DbSQL.getSingleton().releasePreparedStatement(psRead);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TablePassiveScan#insert(long, java.lang.String)
     */
    @Override
    public synchronized RecordPassiveScan insert(long sessionId, String scanName)
            throws DatabaseException {
        SqlPreparedStatementWrapper psInsert = null;
        try {
            psInsert = DbSQL.getSingleton().getPreparedStatement("passivescan.ps.insert");
            psInsert.getPs().setLong(1, sessionId);
            psInsert.getPs().setString(2, scanName);
            psInsert.getPs().executeUpdate();

            int id;
            try (ResultSet rs = psInsert.getLastInsertedId()) {
                rs.next();
                id = rs.getInt(1);
            }
            return read(id);
        } catch (SQLException e) {
            throw new DatabaseException(e);
        } finally {
            DbSQL.getSingleton().releasePreparedStatement(psInsert);
        }
    }

    private RecordPassiveScan build(ResultSet rs) throws DatabaseException {
        try {
            RecordPassiveScan passiveScan = null;
            if (rs.next()) {
                passiveScan =
                        new RecordPassiveScan(
                                rs.getInt(SCANID), rs.getString(SCANNAME), rs.getDate(SCANTIME));
            }
            rs.close();
            return passiveScan;
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }
}
