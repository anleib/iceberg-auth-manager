/*
 * Copyright (C) 2025 Dremio Corporation
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
package com.dremio.iceberg.authmgr.oauth2.tokenexchange;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;
import org.immutables.value.Value;

/**
 * An implementation of {@link SubjectTokenSupplier} specialized for Kubernetes. <br>
 * This class provides mechanisms to fetch Kubernetes identity tokens stored as service account
 * tokens in a predefined file location.
 */
@AuthManagerImmutable
abstract class KubernetesIdentityTokenSupplier extends SubjectTokenSupplier {

  private static final String TOKEN_DEFAULT_LOCATION =
      "/var/run/secrets/kubernetes.io/serviceaccount/token";

  @Value.Default
  protected String tokenLocation() {
    return TOKEN_DEFAULT_LOCATION;
  }

  @Value.Derived
  public Path getTokenPath() {
    return Paths.get(tokenLocation());
  }

  @Override
  public KubernetesIdentityTokenSupplier copy() {
    return ImmutableKubernetesIdentityTokenSupplier.builder()
        .from(this)
        .tokenAgent(getTokenAgent() == null ? null : getTokenAgent().copy())
        .build();
  }

  @Override
  protected Optional<TypelessAccessToken> getStaticToken() {
    if (!Files.isRegularFile(getTokenPath())) {
      throw new IllegalStateException("Token file not found at " + getTokenPath());
    }
    try {
      String value = Files.readString(getTokenPath());
      return Optional.of(new TypelessAccessToken(value));
    } catch (Exception e) {
      throw new RuntimeException(
          "Unable to read token file at: " + getTokenPath() + " due to: " + e.getMessage(), e);
    }
  }

  @Override
  protected TokenTypeURI getTokenType() {
    return TokenTypeURI.JWT;
  }

  @Override
  protected Map<String, String> getDynamicTokenConfig() {
    return Map.of();
  }
}
