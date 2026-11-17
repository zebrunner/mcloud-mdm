# syntax=docker/dockerfile:1
# The Android agent of mcloud-mdm: the launcher of Headwind MDM (hmdm-android, Apache-2.0) with hmdm-android.patch,
# built and signed; the result is an APK, not an image: `make agent` (README.md#android). linux/amd64 only: Google
# publishes aapt2 for linux x86_64 only.
FROM eclipse-temurin:21-jdk-jammy AS build

ARG HMDM_ANDROID_COMMIT=75eff13e7e3faf2fbe0c4d22f42d24da2a139f69
ARG CMDLINE_TOOLS=16111833
ARG CMDLINE_TOOLS_SHA256=0877a1d048fe4a24efe2eff536ca4223f7adeb58648bb81909d33c446918cfa8
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/build-tools/35.0.0:${PATH}
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/tools.zip \
      "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip" \
    && echo "${CMDLINE_TOOLS_SHA256}  /tmp/tools.zip" | sha256sum -c - \
    && mkdir -p "${ANDROID_HOME}/cmdline-tools" \
    && unzip -q /tmp/tools.zip -d "${ANDROID_HOME}/cmdline-tools" \
    && mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm /tmp/tools.zip \
    && { yes || true; } | sdkmanager --licenses > /dev/null \
    && sdkmanager "platforms;android-34" "build-tools;35.0.0" > /dev/null

WORKDIR /src
RUN git init -q . \
    && git fetch -q --depth 1 https://github.com/h-mdm/hmdm-android.git "${HMDM_ANDROID_COMMIT}" \
    && git checkout -q FETCH_HEAD
COPY hmdm-android.patch /tmp/
RUN --mount=type=cache,target=/root/.gradle \
    git apply /tmp/hmdm-android.patch \
    && sh ./gradlew --no-daemon --quiet assembleOpensourceRelease \
    && mkdir /out \
    && zipalign -p 4 app/build/outputs/apk/opensource/release/app-opensource-release-unsigned.apk /out/aligned.apk

# the key of the agent: Android updates a device owner app signed with the same key only, keep it for good
RUN --mount=type=secret,id=agent_keystore,required=true \
    --mount=type=secret,id=agent_keystore_password,required=true \
    apksigner sign --ks /run/secrets/agent_keystore --ks-pass file:/run/secrets/agent_keystore_password \
      --out /out/mcloud-mdm-agent.apk /out/aligned.apk \
    && apksigner verify /out/mcloud-mdm-agent.apk

FROM scratch
COPY --from=build /out/mcloud-mdm-agent.apk /
