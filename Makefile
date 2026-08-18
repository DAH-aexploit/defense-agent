COMPETITION_IMAGE ?= ligacr.azurecr.io/team9/defender:latest
COMPETITION_REPO  := $(firstword $(subst :, ,$(COMPETITION_IMAGE)))
COMPETITION_PLATFORM := linux/amd64

# 라운드 자료가 도착하는 디렉터리. 대회 당일 다운로드 위치에 맞춰 덮어쓴다.
ROUND_SOURCE ?= $(HOME)/Downloads/DAH-리허설
# 통합 배포본 경로. QA의 deployment parity 검사 대상이다.
DEPLOY_DIR := ../deploy/agents/team1/defender
ENGINE_FILES := defender.py detectors.py rehearsal_web_detectors.py protocol_profiles.py signatures.py
HISTORY := qa-results/deploy-history.tsv

.PHONY: qa test bench audit clean-qa \
        competition-push competition-image-check verify-image \
        sync-deploy ship rollback-tag current-digest \
        watch watch-follow round

# ── 검증 ────────────────────────────────────────────────────────────────
qa:
	python3 tools/qa_gate.py

test:
	python3 -m unittest discover -s tests -v

bench:
	python3 tools/bench.py

audit:
	python3 tools/dependency_audit.py

clean-qa:
	rm -f qa-results/latest.json qa-results/latest.md

# ── 라운드 자료 분석 ────────────────────────────────────────────────────
# 새 라운드 자료가 도착하면 1건 처리 후 종료한다. 배경 실행 시 종료가 세션 알림이 된다.
watch:
	python3 tools/round_watch.py "$(ROUND_SOURCE)"

# 라운드마다 재실행하지 않고 계속 감시한다.
watch-follow:
	python3 tools/round_watch.py "$(ROUND_SOURCE)" --follow

# 최신 라운드를 상태와 무관하게 다시 분석한다.
round:
	python3 tools/round_report.py "$(ROUND_SOURCE)"

# ── 배포 ────────────────────────────────────────────────────────────────
# 개발본을 통합 배포본으로 복사한다. QA parity 검사 전에 실행해야 한다.
sync-deploy:
	@test -d "$(DEPLOY_DIR)" || (echo "ERROR: $(DEPLOY_DIR) 없음" >&2; exit 1)
	@for f in $(ENGINE_FILES); do \
		if [ -f "$$f" ]; then cp "$$f" "$(DEPLOY_DIR)/$$f"; echo "sync $$f"; \
		else echo "WARN: $$f 없음, 건너뜀" >&2; fi; \
	done

# 현재 대회 레지스트리에 올라가 있는 이미지의 digest
current-digest:
	@docker manifest inspect $(COMPETITION_IMAGE) >/dev/null 2>&1 || \
		(echo "ERROR: $(COMPETITION_IMAGE) 조회 실패 (docker login 필요)" >&2; exit 1)
	@docker buildx imagetools inspect $(COMPETITION_IMAGE) --format '{{.Manifest.Digest}}' 2>/dev/null || \
		docker manifest inspect $(COMPETITION_IMAGE) | head -20

# 현재 latest를 롤백용 태그로 보존한다. 새 이미지를 밀어넣기 전에 실행한다.
#   make rollback-tag TAG=phase3-pre-reassembly
rollback-tag:
	@test -n "$(TAG)" || (echo "ERROR: TAG=<이름> 필요" >&2; exit 1)
	docker pull --platform $(COMPETITION_PLATFORM) $(COMPETITION_IMAGE)
	docker tag $(COMPETITION_IMAGE) $(COMPETITION_REPO):$(TAG)
	docker push $(COMPETITION_REPO):$(TAG)
	@echo "롤백 태그 생성: $(COMPETITION_REPO):$(TAG)"

# DAH 실행 노드와 동일한 amd64 이미지 생성 및 ACR Push
# Apple Silicon 기본값인 arm64 이미지의 대회 배포 방지
competition-push: qa
	docker buildx build \
		--platform $(COMPETITION_PLATFORM) \
		--provenance=false \
		--sbom=false \
		--tag $(COMPETITION_IMAGE) \
		--push .
	$(MAKE) competition-image-check

# 레지스트리 이미지의 amd64 Pull 및 실제 이미지 설정 검증
competition-image-check:
	docker pull --platform $(COMPETITION_PLATFORM) $(COMPETITION_IMAGE)
	@test "$$(docker image inspect $(COMPETITION_IMAGE) --format '{{.Os}}/{{.Architecture}}')" = "$(COMPETITION_PLATFORM)" || \
		(echo "ERROR: competition image must be $(COMPETITION_PLATFORM)" >&2; exit 1)
	@docker image inspect $(COMPETITION_IMAGE) \
		--format 'verified={{.Os}}/{{.Architecture}} digest={{.Id}} created={{.Created}}'

# Push된 이미지 내부에서 실제 판정을 확인한다. 로컬 QA 통과와 이미지 동작은 별개다.
verify-image:
	docker run --rm --platform $(COMPETITION_PLATFORM) \
		-v "$(CURDIR)/tools/image_verify.py:/tmp/image_verify.py:ro" \
		--entrypoint python $(COMPETITION_IMAGE) /tmp/image_verify.py

# 단일 배포 명령 — 동기화 → QA → amd64 Push → 플랫폼 검증 → 이미지 내부 판정 검증 → 이력 기록
# 코드 수정 후에는 competition-push 대신 이 명령을 사용한다.
ship: sync-deploy competition-push verify-image
	@mkdir -p qa-results
	@test -f $(HISTORY) || printf 'utc\tdigest\timage\tgit\tnote\n' > $(HISTORY)
	@printf '%s\t%s\t%s\t%s\t%s\n' \
		"$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		"$$(docker image inspect $(COMPETITION_IMAGE) --format '{{.Id}}')" \
		"$(COMPETITION_IMAGE)" \
		"$$(git rev-parse --short HEAD 2>/dev/null || echo no-git)" \
		"$(NOTE)" >> $(HISTORY)
	@echo ""
	@echo "═══ 배포 완료 ═══"
	@tail -2 $(HISTORY)
	@echo ""
	@echo "다음 라운드 기동 로그에서 digest 반영을 확인할 것. Push 성공은 반영 성공이 아니다."
