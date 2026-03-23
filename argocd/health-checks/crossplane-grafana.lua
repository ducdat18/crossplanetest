-- Health check Lua script dùng chung cho mọi Crossplane Grafana resource
-- Apply cho: Dashboard, Folder, AlertRule, Organization, OrgMember, DataSource
--
-- ArgoCD đọc status.conditions[] của Crossplane CRD để xác định health:
--   Ready=True      → Healthy
--   Ready=False     → Degraded (kèm message lý do)
--   Synced=False    → Progressing
--   (không có gì)   → Progressing (đang tạo lần đầu)

local health_status = {}

-- Chưa có status (resource vừa được tạo, Crossplane chưa reconcile)
if obj.status == nil or obj.status.conditions == nil then
  health_status.status = "Progressing"
  health_status.message = "Waiting for Crossplane to reconcile..."
  return health_status
end

local ready_condition = nil
local synced_condition = nil

for _, condition in ipairs(obj.status.conditions) do
  if condition.type == "Ready" then
    ready_condition = condition
  end
  if condition.type == "Synced" then
    synced_condition = condition
  end
end

-- Chưa có Ready condition
if ready_condition == nil then
  health_status.status = "Progressing"
  health_status.message = "Crossplane reconciliation in progress..."
  return health_status
end

-- Synced=False → đang apply hoặc bị lỗi tạm thời
if synced_condition ~= nil and synced_condition.status == "False" then
  health_status.status = "Progressing"
  health_status.message = synced_condition.message or "Syncing with Grafana API..."
  return health_status
end

-- Ready=True → hoàn toàn healthy
if ready_condition.status == "True" then
  health_status.status = "Healthy"
  -- Hiện thị thêm thông tin từ atProvider nếu có
  if obj.status.atProvider ~= nil then
    local info = {}
    if obj.status.atProvider.id ~= nil then
      table.insert(info, "id=" .. tostring(obj.status.atProvider.id))
    end
    if obj.status.atProvider.uid ~= nil then
      table.insert(info, "uid=" .. tostring(obj.status.atProvider.uid))
    end
    if obj.status.atProvider.orgId ~= nil then
      table.insert(info, "orgId=" .. tostring(obj.status.atProvider.orgId))
    end
    if #info > 0 then
      health_status.message = table.concat(info, ", ")
    end
  end
  return health_status
end

-- Ready=False với reason=ReconcileError → Degraded
if ready_condition.status == "False" then
  local reason = ready_condition.reason or "Unknown"
  local message = ready_condition.message or "Crossplane failed to sync with Grafana"

  -- Phân biệt lỗi tạm thời vs lỗi cứng
  if reason == "ReconcileError" or reason == "ApplyFailed" then
    health_status.status = "Degraded"
    health_status.message = "[" .. reason .. "] " .. message
  elseif reason == "ReconcilePaused" then
    health_status.status = "Suspended"
    health_status.message = "Reconciliation paused by admin"
  else
    health_status.status = "Progressing"
    health_status.message = "[" .. reason .. "] " .. message
  end
  return health_status
end

-- Fallback
health_status.status = "Unknown"
health_status.message = "Cannot determine health from status conditions"
return health_status
