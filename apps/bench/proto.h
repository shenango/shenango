// a really basic encoding for experiment messages

#pragma once

// The netbench server responds to this port.
constexpr uint64_t kNetbenchPort = 8001;

constexpr uint32_t kMagic = 0x6e626368; // 'nbch'
constexpr uint32_t kKill = 0x6b696c6c; // 'kill'

struct nbench_req {
  uint32_t magic;
  int nports;
};

struct nbench_resp {
  uint32_t magic;
  int nports;
  uint16_t ports[];
};

struct payload {
  uint32_t tag;
  uint64_t idx;
  double workn;
  char pad[];
};
