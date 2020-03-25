/*
 *
 * Paros and its related class files.
 *
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 *
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2011/05/27 Ensure all PreparedStatements and ResultSets closed to prevent leaks
// ZAP: 2012/04/23 Added @Override annotation to the appropriate method.
// ZAP: 2012/08/08 Upgrade to HSQLDB 2.x (introduced TABLE_NAME constant + DbUtils)
// ZAP: 2014/03/23 Changed to use try-with-resource statements.
// ZAP: 2015/02/09 Issue 1525: Introduce a database interface layer to allow for alternative
// implementations
// ZAP: 2019/06/01 Normalise line endings.
// ZAP: 2019/06/05 Normalise format/style.
package org.parosproxy.paros.db.paros;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordPassiveScan;
import org.parosproxy.paros.db.TablePassiveScan;

public class ParosTablePassiveScan extends ParosAbstractTable implements TablePassiveScan {

    private static final String TABLE_NAME = "PASSIVESCAN";

    private static final String SCANID = "SCANID";
    private static final String SESSIONID = "SESSIONID";
    private static final String SCANNAME = "SCANNAME";
    private static final String SCANTIME = "SCANTIME";

    private PreparedStatement psRead = null;
    private PreparedStatement psInsert = null;
    private CallableStatement psGetIdLastInsert = null;

    // private PreparedStatement psUpdate = null;

    public ParosTablePassiveScan() {}

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            psRead =
                    conn.prepareStatement(
                            "SELECT * FROM " + TABLE_NAME + " WHERE " + SCANID + " = ?");
            psInsert =
                    conn.prepareStatement(
                            "INSERT INTO PASSIVESCAN (" + SESSIONID + "," + SCANNAME + ") VALUES (?, ?)");
            psGetIdLastInsert = conn.prepareCall("CALL IDENTITY();");
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableScan#getLatestPassiveScan()
     */
    @Override
    public synchronized RecordPassiveScan getLatestPassiveScan() throws DatabaseException {
        try {
            try (PreparedStatement psLatest =
                    getConnection()
                            .prepareStatement(
                                    "SELECT * FROM PASSIVESCAN WHERE SCANID = (SELECT MAX(B.SCANID) FROM PASSIVESCAN AS B)")) {
                try (ResultSet rs = psLatest.executeQuery()) {
                    RecordPassiveScan result = build(rs);
                    return result;
                }
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TablePassiveScan#read(int)
     */
    @Override
    public synchronized RecordPassiveScan read(int passiveScanId) throws DatabaseException {
        try {
            psRead.setInt(1, passiveScanId);

            try (ResultSet rs = psRead.executeQuery()) {
                RecordPassiveScan result = build(rs);
                return result;
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TablePassiveScan#insert(long, java.lang.String)
     */
    @Override
    public synchronized RecordPassiveScan insert(long sessionId, String passiveScanName)
            throws DatabaseException {
        try {
            psInsert.setLong(1, sessionId);
            psInsert.setString(2, passiveScanName);
            psInsert.executeUpdate();

            int id;
            try (ResultSet rs = psGetIdLastInsert.executeQuery()) {
                rs.next();
                id = rs.getInt(1);
            }
            return read(id);
        } catch (SQLException e) {
            throw new DatabaseException(e);
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
