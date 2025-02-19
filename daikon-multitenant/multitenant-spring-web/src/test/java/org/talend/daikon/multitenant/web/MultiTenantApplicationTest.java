// ============================================================================
//
// Copyright (C) 2006-2017 Talend Inc. - www.talend.com
//
// This source code is available under agreement available at
// %InstallDIR%\features\org.talend.rcp.branding.%PRODUCTNAME%\%PRODUCTNAME%license.txt
//
// You should have received a copy of the agreement
// along with this program; if not, write to Talend SA
// 9 rue Pages 92150 Suresnes, France
//
// ============================================================================
package org.talend.daikon.multitenant.web;

import static com.jayway.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.talend.daikon.multitenant.web.MultiTenantApplication.MESSAGE;

import com.jayway.restassured.RestAssured;
import org.apache.log4j.MDC;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.talend.daikon.logging.event.field.MdcKeys;
import org.talend.daikon.multitenant.context.TenancyContextHolder;

@ExtendWith(SpringExtension.class)
@Import(MultiTenantApplicationTest.SampleRequestHandlerConfiguration.class)
@SpringBootTest(classes = { MultiTenantApplication.class }, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class MultiTenantApplicationTest {

    @Value("${local.server.port}")
    public int port;

    @Autowired
    private SampleRequestHandlerConfiguration handlerConfiguration;

    @BeforeEach
    public void setUp() throws Exception {
        RestAssured.port = port;
        handlerConfiguration.verifier = () -> {
        };
    }

    @Test
    public void testSyncWithoutTenant() {
        handlerConfiguration.verifier = () -> {
            assertFalse(TenancyContextHolder.getContext().getOptionalTenant().isPresent());
            assertNull(MDC.get(MdcKeys.ACCOUNT_ID));
        };
        given().get("/sync").then().statusCode(200).body(Matchers.equalTo(MESSAGE));
    }

    @Test
    public void testSyncWithTenantHeader() {
        String tenantId = "MyTestTenantId";
        handlerConfiguration.verifier = () -> {
            assertEquals(tenantId, TenancyContextHolder.getContext().getTenant().getIdentity());
            assertEquals(tenantId, MDC.get(MdcKeys.ACCOUNT_ID));
        };
        given().header(MultiTenantApplication.TENANT_HTTP_HEADER, tenantId).get("/sync").then().statusCode(200)
                .body(Matchers.equalTo(MESSAGE));
    }

    @Test
    public void testAsyncWithoutTenant() {
        handlerConfiguration.verifier = () -> {
            assertFalse(TenancyContextHolder.getContext().getOptionalTenant().isPresent());
            assertNull(MDC.get(MdcKeys.ACCOUNT_ID));
        };
        given().get("/async").then().statusCode(200).body(Matchers.equalTo(MESSAGE));
    }

    @Test
    public void testAsyncWithTenantHeader() {
        String tenantId = "MyAsyncTestTenantId";
        handlerConfiguration.verifier = () -> {
            assertEquals(tenantId, TenancyContextHolder.getContext().getTenant().getIdentity());
            assertEquals(tenantId, MDC.get(MdcKeys.ACCOUNT_ID));
        };
        given().header(MultiTenantApplication.TENANT_HTTP_HEADER, tenantId).get("/async").then().statusCode(200)
                .body(Matchers.equalTo(MESSAGE));
    }

    @Test
    public void testSyncWithTenantAndError() {
        String errorMessage = "Expected error message";
        String tenantId = "MyTestTenantId";
        handlerConfiguration.verifier = () -> {
            assertEquals(tenantId, TenancyContextHolder.getContext().getTenant().getIdentity());
            assertEquals(tenantId, MDC.get(MdcKeys.ACCOUNT_ID));
            throw new RuntimeException(errorMessage);
        };
        given().header(MultiTenantApplication.TENANT_HTTP_HEADER, tenantId).get("/sync").then().statusCode(500);
    }

    @Test
    public void testAsyncWithTenantAndError() {
        String errorMessage = "Expected error message";
        String tenantId = "MyTestTenantId";
        handlerConfiguration.verifier = () -> {
            assertEquals(tenantId, TenancyContextHolder.getContext().getTenant().getIdentity());
            assertEquals(tenantId, MDC.get(MdcKeys.ACCOUNT_ID));
            throw new RuntimeException(errorMessage);
        };
        given().header(MultiTenantApplication.TENANT_HTTP_HEADER, tenantId).get("/async").then().statusCode(500);
    }

    @Configuration
    public static class SampleRequestHandlerConfiguration {

        public Runnable verifier = () -> {
        };

        @Bean
        public MultiTenantApplication.SampleRequestHandler sampleRequestHandler() {
            return () -> verifier.run();
        }
    }

}
