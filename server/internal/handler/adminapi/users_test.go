package adminapi

import (
	"encoding/json"
	"testing"
	"time"
)

// TestGroupReqDistinguishesMissingAndNull 覆盖「清空有效期」的请求解析。
//
// 管理页把有效期留空时发的是 "expire_at": null，而字段缺失表示「这次不改」。
// 两者都被解成 nil 的话，「清空」会退化成空操作：旧到期时间残留，到期调度
// 随后把刚改派的用户迁回默认分组。这里钉住三态的区分。
func TestGroupReqDistinguishesMissingAndNull(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantSet bool
		wantNil bool
	}{
		{"字段缺失表示不修改", `{"group_id":3}`, false, true},
		{"显式 null 表示清除", `{"group_id":3,"expire_at":null}`, true, true},
		{"具体时间表示设为该时刻", `{"group_id":3,"expire_at":"2026-11-01T08:00:00Z"}`, true, false},
	}

	for _, tc := range cases {
		var req groupReq
		if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
			t.Fatalf("%s: 解析失败: %v", tc.name, err)
		}
		if req.ExpireAt.Set != tc.wantSet {
			t.Fatalf("%s: Set=%v，期望 %v", tc.name, req.ExpireAt.Set, tc.wantSet)
		}
		if !tc.wantSet {
			continue
		}
		if gotNil := req.ExpireAt.Value == nil; gotNil != tc.wantNil {
			t.Fatalf("%s: Value 为空=%v，期望 %v", tc.name, gotNil, tc.wantNil)
		}
		if tc.wantNil {
			continue
		}
		want, err := time.Parse(time.RFC3339, "2026-11-01T08:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if !req.ExpireAt.Value.Equal(want) {
			t.Fatalf("%s: 时间解析错误，实际 %v", tc.name, req.ExpireAt.Value)
		}
	}
}
