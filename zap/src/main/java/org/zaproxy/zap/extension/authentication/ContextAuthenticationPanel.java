/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.authentication;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationIndicatorsPanel;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.LayoutHelper;

/** The Context Panel shown for configuring a Context's authentication methods. */
public class ContextAuthenticationPanel extends AbstractContextPropertiesPanel {

    private static final Logger log = Logger.getLogger(ContextAuthenticationPanel.class);
    private static final long serialVersionUID = -898084998156067286L;

    /** The Constant PANEL NAME. */
    private static final String PANEL_NAME =
            Constant.messages.getString("authentication.panel.title");

    private static final String FIELD_LABEL_LOGGED_IN_INDICATOR =
            Constant.messages.getString("authentication.panel.label.loggedIn");
    private static final String FIELD_LABEL_LOGGED_OUT_INDICATOR =
            Constant.messages.getString("authentication.panel.label.loggedOut");
    private static final String FIELD_LABEL_TYPE_SELECT =
            Constant.messages.getString("authentication.panel.label.typeSelect");
    private static final String LABEL_DESCRIPTION =
            Constant.messages.getString("authentication.panel.label.description");
    private static final String PANEL_TITLE_CONFIG =
            Constant.messages.getString("authentication.panel.label.configTitle");
    private static final String LABEL_CONFIG_NOT_NEEDED =
            Constant.messages.getHtmlWrappedString("sessionmanagement.panel.label.noConfigPanel");

    /** The extension. */
    private ExtensionAuthentication extension;

    /** The authentication method types combo box. */
    private JComboBox<AuthenticationMethodType> authenticationMethodsComboBox;

    /** The selected authentication method. */
    private AuthenticationMethod selectedAuthenticationMethod;

    /** The shown method type. */
    private AuthenticationMethodType shownMethodType;

    /** The shown config panel. */
    private AbstractAuthenticationMethodOptionsPanel shownConfigPanel;

    /** The container panel for the authentication method's configuration. */
    private JPanel configContainerPanel;

    private ZapTextField loggedInIndicatorRegexField = null;
    private ZapTextField loggedOutIndicatorRegexField = null;

    /** Hacked used to make sure a confirmation is not needed if changes where done during init. */
    private boolean needsConfirm = true;

    private AuthenticationIndicatorsPanel authenticationIndicatorsPanel;

    /**
     * Instantiates a new context authentication configuration panel.
     *
     * @param extension the extension
     * @param context the context
     */
    public ContextAuthenticationPanel(ExtensionAuthentication extension, Context context) {
        super(context.getId());
        this.extension = extension;
        initialize();
    }

    public static String buildName(int contextId) {
        return contextId + ": " + PANEL_NAME;
    }

    /** Initialize the panel. */
    private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(buildName(getContextId()));
        this.setLayout(new GridBagLayout());
        this.setBorder(new EmptyBorder(2, 2, 2, 2));

        this.add(new JLabel(LABEL_DESCRIPTION), LayoutHelper.getGBC(0, 0, 1, 1.0D));

        // Method type combo box
        this.add(
                new JLabel(FIELD_LABEL_TYPE_SELECT),
                LayoutHelper.getGBC(0, 1, 1, 1.0D, new Insets(20, 0, 5, 5)));
        this.add(getAuthenticationMethodsComboBox(), LayoutHelper.getGBC(0, 2, 1, 1.0D));

        // Method config panel container
        this.add(
                getConfigContainerPanel(),
                LayoutHelper.getGBC(0, 3, 1, 1.0d, new Insets(10, 0, 10, 0)));

        // Logged In/Out indicators
        this.add(new JLabel(FIELD_LABEL_LOGGED_IN_INDICATOR), LayoutHelper.getGBC(0, 4, 1, 1.0D));
        this.add(getLoggedInIndicatorRegexField(), LayoutHelper.getGBC(0, 5, 1, 1.0D));
        this.add(new JLabel(FIELD_LABEL_LOGGED_OUT_INDICATOR), LayoutHelper.getGBC(0, 6, 1, 1.0D));
        this.add(getLoggedOutIndicatorRegexField(), LayoutHelper.getGBC(0, 7, 1, 1.0D));

        // Padding
        this.add(new JLabel(), LayoutHelper.getGBC(0, 99, 1, 1.0D, 1.0D));
    }

    /**
     * Changes the shown method's configuration panel (used to display brief info about the method
     * and configure it) with a new one, based on a new method type. If {@code null} is provided as
     * a parameter, nothing is shown. If the provided method type does not require configuration, a
     * simple message is shown stating that no configuration is needed.
     *
     * @param newMethodType the new method type. If null, nothing is shown.
     */
    private void changeMethodConfigPanel(AuthenticationMethodType newMethodType) {
        // If there's no new method, don't display anything
        if (newMethodType == null) {
            getConfigContainerPanel().removeAll();
            getConfigContainerPanel().setVisible(false);
            this.shownMethodType = null;
            return;
        }

        // If a panel of the correct type is already shown, do nothing
        if (shownMethodType != null
                && newMethodType.getClass().equals(shownMethodType.getClass())) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Creating new panel for configuring: " + newMethodType.getName());
        }
        this.getConfigContainerPanel().removeAll();

        // show the panel according to whether the authentication type needs configuration
        if (newMethodType.hasOptionsPanel()) {
            shownConfigPanel = newMethodType.buildOptionsPanel(getUISharedContext());
            getConfigContainerPanel().add(shownConfigPanel, BorderLayout.CENTER);
        } else {
            shownConfigPanel = null;
            getConfigContainerPanel().add(new JLabel(LABEL_CONFIG_NOT_NEEDED), BorderLayout.CENTER);
        }
        this.shownMethodType = newMethodType;

        this.getConfigContainerPanel().setVisible(true);
        this.getConfigContainerPanel().revalidate();
    }

    /**
     * Gets the authentication method types combo box.
     *
     * @return the authentication methods combo box
     */
    protected JComboBox<AuthenticationMethodType> getAuthenticationMethodsComboBox() {
        if (authenticationMethodsComboBox == null) {
            Vector<AuthenticationMethodType> methods =
                    new Vector<>(extension.getAuthenticationMethodTypes());
            authenticationMethodsComboBox = new JComboBox<>(methods);
            authenticationMethodsComboBox.setSelectedItem(null);

            // Prepare the listener for the change of selection
            authenticationMethodsComboBox.addItemListener(
                    new ItemListener() {

                        @Override
                        public void itemStateChanged(ItemEvent e) {
                            if (e.getStateChange() == ItemEvent.SELECTED
                                    && !e.getItem().equals(shownMethodType)) {
                                log.debug("Selected new Authentication type: " + e.getItem());

                                AuthenticationMethodType type =
                                        ((AuthenticationMethodType) e.getItem());
                                if (shownMethodType == null
                                        || type.getAuthenticationCredentialsType()
                                                != shownMethodType
                                                        .getAuthenticationCredentialsType()) {

                                    if (needsConfirm && !confirmAndResetUsersCredentials(type)) {
                                        log.debug("Cancelled change of authentication type.");

                                        authenticationMethodsComboBox.setSelectedItem(
                                                shownMethodType);
                                        return;
                                    }
                                }
                                resetLoggedInOutIndicators();

                                // If no authentication method was previously selected or it's a
                                // different
                                // class, create a new authentication method object
                                if (selectedAuthenticationMethod == null
                                        || !type.isTypeForMethod(selectedAuthenticationMethod)) {
                                    selectedAuthenticationMethod =
                                            type.createAuthenticationMethod(getContextId());
                                }

                                // Show the configuration panel
                                changeMethodConfigPanel(type);
                                if (type.hasOptionsPanel()) {
                                    shownConfigPanel.bindMethod(
                                            selectedAuthenticationMethod,
                                            getAuthenticationIndicatorsPanel());
                                }
                            }
                        }
                    });
        }
        return authenticationMethodsComboBox;
    }

    private AuthenticationIndicatorsPanel getAuthenticationIndicatorsPanel() {
        if (authenticationIndicatorsPanel == null) {
            authenticationIndicatorsPanel = new AuthenticationIndicatorsPanelImpl();
        }
        return authenticationIndicatorsPanel;
    }

    /**
     * Make sure the user acknowledges the Users corresponding to this context will have the
     * credentials changed with the new type of authentication method.
     *
     * @param type the type of authentication method being set.
     * @return true, if successful
     */
    private boolean confirmAndResetUsersCredentials(AuthenticationMethodType type) {
        ExtensionUserManagement usersExtension =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
        if (usersExtension == null) {
            return true;
        }
        List<User> users = usersExtension.getSharedContextUsers(getUISharedContext());
        if (users.isEmpty()) {
            return true;
        }
        if (users.stream().anyMatch(user -> user.getAuthenticationCredentials().isConfigured())) {
            authenticationMethodsComboBox.transferFocus();
            int choice =
                    JOptionPane.showConfirmDialog(
                            this,
                            Constant.messages.getString(
                                    "authentication.dialog.confirmChange.label"),
                            Constant.messages.getString(
                                    "authentication.dialog.confirmChange.title"),
                            JOptionPane.OK_CANCEL_OPTION);
            if (choice == JOptionPane.CANCEL_OPTION) {
                return false;
            }
        }
        users.replaceAll(
                user -> {
                    User modifiedUser = new User(user.getContextId(), user.getName(), user.getId());
                    modifiedUser.setEnabled(false);
                    modifiedUser.setAuthenticationCredentials(
                            type.createAuthenticationCredentials());
                    return modifiedUser;
                });
        return true;
    }

    private JPanel getConfigContainerPanel() {
        if (configContainerPanel == null) {
            configContainerPanel = new JPanel(new BorderLayout());
            configContainerPanel.setBorder(
                    javax.swing.BorderFactory.createTitledBorder(
                            null,
                            PANEL_TITLE_CONFIG,
                            javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                            javax.swing.border.TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard),
                            java.awt.Color.black));
        }
        return configContainerPanel;
    }

    private ZapTextField getLoggedInIndicatorRegexField() {
        if (loggedInIndicatorRegexField == null) loggedInIndicatorRegexField = new ZapTextField();
        return loggedInIndicatorRegexField;
    }

    private ZapTextField getLoggedOutIndicatorRegexField() {
        if (loggedOutIndicatorRegexField == null) loggedOutIndicatorRegexField = new ZapTextField();
        return loggedOutIndicatorRegexField;
    }

    @Override
    public String getHelpIndex() {
        return "ui.dialogs.context-auth";
    }

    @Override
    public void initContextData(Session session, Context uiSharedContext) {
        selectedAuthenticationMethod = uiSharedContext.getAuthenticationMethod();
        if (log.isDebugEnabled())
            log.debug(
                    "Initializing configuration panel for authentication method: "
                            + selectedAuthenticationMethod
                            + " for context "
                            + uiSharedContext.getName());

        resetLoggedInOutIndicators();

        // If something was already configured, find the type and set the UI accordingly
        if (selectedAuthenticationMethod != null) {
            // Set logged in/out indicators
            if (selectedAuthenticationMethod.getLoggedInIndicatorPattern() != null)
                getLoggedInIndicatorRegexField()
                        .setText(
                                selectedAuthenticationMethod
                                        .getLoggedInIndicatorPattern()
                                        .pattern());
            else getLoggedInIndicatorRegexField().setText("");
            if (selectedAuthenticationMethod.getLoggedOutIndicatorPattern() != null)
                getLoggedOutIndicatorRegexField()
                        .setText(
                                selectedAuthenticationMethod
                                        .getLoggedOutIndicatorPattern()
                                        .pattern());
            else getLoggedOutIndicatorRegexField().setText("");

            // If the proper type is already selected, just rebind the data
            if (shownMethodType != null
                    && shownMethodType.isTypeForMethod(selectedAuthenticationMethod)) {
                if (shownMethodType.hasOptionsPanel()) {
                    log.debug(
                            "Binding authentication method to existing panel of proper type for context "
                                    + uiSharedContext.getName());
                    shownConfigPanel.bindMethod(
                            selectedAuthenticationMethod, getAuthenticationIndicatorsPanel());
                }
                return;
            }

            // Select what needs to be selected
            for (AuthenticationMethodType type : extension.getAuthenticationMethodTypes())
                if (type.isTypeForMethod(selectedAuthenticationMethod)) {
                    // Selecting the type here will also force the selection listener to run and
                    // change the config panel accordingly
                    log.debug(
                            "Binding authentication method to new panel of proper type for context "
                                    + uiSharedContext.getName());
                    // Add hack to make sure no confirmation is needed if a change has been done
                    // somewhere else (e.g. API)
                    needsConfirm = false;
                    getAuthenticationMethodsComboBox().setSelectedItem(type);
                    needsConfirm = true;
                    break;
                }
        }
    }

    /**
     * Resets the tool tip and enables the fields of the logged in/out indicators.
     *
     * @see #getLoggedInIndicatorRegexField()
     * @see #getLoggedOutIndicatorRegexField()
     */
    private void resetLoggedInOutIndicators() {
        getLoggedInIndicatorRegexField().setToolTipText(null);
        getLoggedInIndicatorRegexField().setEnabled(true);
        getLoggedOutIndicatorRegexField().setToolTipText(null);
        getLoggedOutIndicatorRegexField().setEnabled(true);
    }

    @Override
    public void validateContextData(Session session) throws Exception {
        if (shownConfigPanel != null) shownConfigPanel.validateFields();
        try {
            Pattern.compile(getLoggedInIndicatorRegexField().getText());
            Pattern.compile(getLoggedOutIndicatorRegexField().getText());
        } catch (PatternSyntaxException e) {
            throw new IllegalStateException(
                    Constant.messages.getString(
                            "authentication.panel.error.illegalPattern",
                            getUISharedContext().getName()),
                    e);
        }
    }

    private void saveMethod() {
        if (shownConfigPanel != null) shownConfigPanel.saveMethod();
        selectedAuthenticationMethod.setLoggedInIndicatorPattern(
                getLoggedInIndicatorRegexField().getText());
        selectedAuthenticationMethod.setLoggedOutIndicatorPattern(
                getLoggedOutIndicatorRegexField().getText());
    }

    @Override
    public void saveContextData(Session session) throws Exception {
        saveMethod();

        Context context = session.getContext(getContextId());
        // Notify the previously saved method that it's being discarded so the changes can be
        // reflected in the UI
        if (context.getAuthenticationMethod() != null)
            if (!shownMethodType.isTypeForMethod(context.getAuthenticationMethod()))
                context.getAuthenticationMethod().onMethodDiscarded();

        context.setAuthenticationMethod(selectedAuthenticationMethod);

        // Notify the newly saved method that it's being persisted so the changes can be
        // reflected in the UI
        selectedAuthenticationMethod.onMethodPersisted();
    }

    @Override
    public void saveTemporaryContextData(Context uiSharedContext) {
        saveMethod();
        uiSharedContext.setAuthenticationMethod(selectedAuthenticationMethod);
    }

    private class AuthenticationIndicatorsPanelImpl implements AuthenticationIndicatorsPanel {

        @Override
        public String getLoggedInIndicatorPattern() {
            return getLoggedInIndicatorRegexField().getText();
        }

        @Override
        public void setLoggedInIndicatorPattern(String loggedInIndicatorPattern) {
            getLoggedInIndicatorRegexField().setText(loggedInIndicatorPattern);
        }

        @Override
        public void setLoggedInIndicatorEnabled(boolean enabled) {
            getLoggedInIndicatorRegexField().setEnabled(enabled);
        }

        @Override
        public void setLoggedInIndicatorToolTip(String toolTip) {
            getLoggedInIndicatorRegexField().setToolTipText(toolTip);
        }

        @Override
        public String getLoggedOutIndicatorPattern() {
            return getLoggedOutIndicatorRegexField().getText();
        }

        @Override
        public void setLoggedOutIndicatorPattern(String loggedOutIndicatorPattern) {
            getLoggedOutIndicatorRegexField().setText(loggedOutIndicatorPattern);
        }

        @Override
        public void setLoggedOutIndicatorEnabled(boolean enabled) {
            getLoggedOutIndicatorRegexField().setEnabled(enabled);
        }

        @Override
        public void setLoggedOutIndicatorToolTip(String toolTip) {
            getLoggedOutIndicatorRegexField().setToolTipText(toolTip);
        }
    }
}
