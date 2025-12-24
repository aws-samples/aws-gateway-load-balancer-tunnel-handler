# NO_RETURN_TRAFFIC Mode Architecture Documentation

## Change Summary

**Date**: December 3, 2025  
**Component**: Gateway Load Balancer Tunnel Handler (gwlbtun)  
**File Modified**: `utils.h`  
**Change Type**: Configuration - Performance Optimization Mode

### Modification Details

The `NO_RETURN_TRAFFIC` preprocessor directive has been **enabled** in `utils.h` (line 33):

```cpp
// Before:
//#define NO_RETURN_TRAFFIC

// After:
#define NO_RETURN_TRAFFIC
```

## Architectural Impact

### 1. System Architecture Changes

#### Traffic Flow Model

**Previous State (Two-Arm Mode)**:
- Bidirectional traffic flow through GWLB
- Ingress interface: `gwi-<X>` 
- Egress interface: `gwo-<X>`
- Return traffic sent back to GWLB via egress interface

**Current State (One-Arm/Receive-Only Mode)**:
- Unidirectional traffic flow from GWLB
- Ingress interface only: `gwi-<X>`
- **No egress interface created** (`gwo-<X>` interfaces removed)
- No return traffic capability to GWLB

```
┌─────────────────────────────────────────────────────────────┐
│                    NO_RETURN_TRAFFIC Mode                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  GWLB Endpoint  ──────────────────────────────────────────►  │
│                                                               │
│  ┌──────────────┐         ┌─────────────────┐               │
│  │ UDP Receiver │────────►│ Geneve Handler  │               │
│  └──────────────┘         └─────────────────┘               │
│                                    │                          │
│                                    ▼                          │
│                           ┌─────────────────┐                │
│                           │  gwi-<X> Only   │                │
│                           │ (Ingress Tun)   │                │
│                           └─────────────────┘                │
│                                    │                          │
│                                    ▼                          │
│                           ┌─────────────────┐                │
│                           │ Linux Network   │                │
│                           │ Stack/iptables  │                │
│                           └─────────────────┘                │
│                                                               │
│  ◄─────────────────────────────────────────  No Return Path  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 2. Component-Level Changes

#### Removed Components

1. **Egress Tunnel Interfaces (`gwo-<X>`)**
   - No longer created or managed
   - Hook scripts receive empty/null egress interface parameter

2. **Flow Cookie Tracking System**
   - `gwlbV4Cookies` FlowCache removed from GeneveHandlerENI
   - `gwlbV6Cookies` FlowCache removed from GeneveHandlerENI
   - No flow state maintenance required

3. **Return Path Processing**
   - `tunReceiverCallback()` functionality disabled
   - No packet processing from tunnel back to GWLB
   - No GwlbData cookie lookups

#### Modified Components

**GeneveHandlerENI Class** (`GeneveHandler.h`):
```cpp
// Conditional compilation removes:
#ifndef NO_RETURN_TRAFFIC
    std::unique_ptr<TunInterface> tunnelOut;
    FlowCache<PacketHeaderV4, GwlbData> gwlbV4Cookies;
    FlowCache<PacketHeaderV6, GwlbData> gwlbV6Cookies;
#endif
```

**Health Check System** (`GeneveHandlerENIHealthCheck`):
- Simplified health reporting
- No egress tunnel statistics
- No flow cache statistics (v4/v6)

### 3. Data Flow Changes

#### Ingress Path (Unchanged)
1. UDP packets received from GWLB endpoint
2. Geneve header parsed and validated
3. Inner IP packet extracted
4. Packet written to `gwi-<X>` tunnel interface
5. Linux network stack processes packet

#### Egress Path (Removed)
- ~~Packets from Linux stack to `gwo-<X>` interface~~
- ~~Flow cookie lookup for GWLB routing~~
- ~~Geneve re-encapsulation~~
- ~~UDP transmission back to GWLB~~

### 4. Performance Implications

#### Performance Improvements

1. **Memory Reduction**
   - No flow cache memory allocation
   - No egress tunnel interface buffers
   - Reduced per-ENI memory footprint

2. **CPU Efficiency**
   - No flow cache synchronization overhead
   - No hash table lookups on ingress path
   - No cookie insertion/maintenance
   - Reduced lock contention in multi-threaded scenarios

3. **Simplified Threading**
   - No egress tunnel processing threads
   - Reduced thread synchronization points
   - Better cache locality

#### Performance Trade-offs

1. **Asymmetric Routing**
   - Return traffic must use alternative path
   - May cause routing complexity elsewhere
   - Potential for asymmetric flow handling

2. **Stateless Operation**
   - Cannot correlate request/response flows
   - No bidirectional flow tracking
   - Limited visibility into complete conversations

### 5. Configuration Impact

#### Hook Scripts

**Modified Behavior**:
- Hook scripts still called on tunnel creation/destruction
- Egress interface parameter (argument 3) will be empty or null
- Scripts must handle single-interface mode

**Example Hook Script Adaptation**:
```bash
#!/bin/bash
# Hook script for NO_RETURN_TRAFFIC mode

OPERATION=$1
INGRESS_IF=$2
EGRESS_IF=$3  # Will be empty in NO_RETURN_TRAFFIC mode
ENI_ID=$4

if [ "$OPERATION" = "CREATE" ]; then
    # Disable reverse path filtering on ingress interface
    sysctl net.ipv4.conf.$INGRESS_IF.rp_filter=0
    
    # No egress interface configuration needed
    # if [ -n "$EGRESS_IF" ]; then
    #     sysctl net.ipv4.conf.$EGRESS_IF.rp_filter=0
    # fi
fi
```

#### Kernel Parameters

**Still Required**:
- `net.ipv4.conf.gwi-*.rp_filter=0` (reverse path filter disable)
- `net.ipv4.ip_forward=1` (if forwarding to other interfaces)
- `net.ipv6.conf.all.forwarding=1` (for IPv6 forwarding)

**No Longer Relevant**:
- Egress interface-specific sysctls

### 6. Use Case Alignment

#### Ideal Use Cases

1. **Traffic Monitoring/Inspection Only**
   - IDS/IPS systems that only inspect traffic
   - Logging and analytics appliances
   - Passive security monitoring

2. **One-Way Traffic Mirroring**
   - Traffic replication to monitoring tools
   - Compliance recording systems
   - Network forensics

3. **Decapsulation-Only Scenarios**
   - Traffic forwarding to other systems
   - Integration with external routing

#### Incompatible Use Cases

1. **Active Inline Security**
   - Firewalls requiring bidirectional flow
   - NAT gateways
   - Proxy services

2. **Stateful Inspection**
   - Application-layer gateways
   - Deep packet inspection requiring response correlation
   - Connection tracking systems

### 7. Integration Points

#### Upstream Systems (GWLB)
- **No changes required** to GWLB configuration
- GWLB continues sending traffic normally
- GWLB health checks still function (if configured)

#### Downstream Systems
- Must handle return traffic via alternative paths
- Cannot rely on gwlbtun for response routing
- May need separate routing configuration

### 8. Monitoring and Observability

#### Health Check Changes

**Removed Metrics**:
- Egress tunnel packet/byte counters
- Flow cache size and timeout statistics
- Bidirectional flow correlation data

**Retained Metrics**:
- Ingress tunnel packet/byte counters
- UDP receiver statistics
- Per-ENI ingress traffic rates
- Last packet timestamp per ENI

#### Health Check Output Example

```json
{
  "healthy": true,
  "eni": "2b8ee1d4db0c51c4",
  "ingress": {
    "interface": "gwi-abc123",
    "packets": 1234567,
    "bytes": 987654321,
    "last_packet": "2025-12-03T10:30:45Z"
  }
  // No egress or flow cache sections
}
```

### 9. Security Considerations

#### Security Posture Changes

**Improvements**:
- Reduced attack surface (no egress path)
- Simpler code paths reduce vulnerability potential
- No flow state to poison or exhaust

**Considerations**:
- Asymmetric routing may complicate security policies
- Cannot implement inline blocking/filtering
- Limited to passive security monitoring

#### Threat Model Impact

**Mitigated Threats**:
- Flow cache exhaustion attacks
- Cookie spoofing/manipulation
- Egress path injection attacks

**Unchanged Threats**:
- Ingress packet flooding
- Geneve header manipulation
- UDP source spoofing

### 10. Migration and Rollback

#### Enabling NO_RETURN_TRAFFIC Mode

1. Modify `utils.h` to uncomment `#define NO_RETURN_TRAFFIC`
2. Recompile: `cmake3 .; make`
3. Update hook scripts to handle single interface
4. Configure alternative return path routing
5. Deploy and test with monitoring

#### Rollback Procedure

1. Comment out `#define NO_RETURN_TRAFFIC` in `utils.h`
2. Recompile: `cmake3 .; make`
3. Restore hook scripts for dual-interface mode
4. Restart gwlbtun service
5. Verify bidirectional traffic flow

### 11. Testing Recommendations

#### Functional Testing

1. **Ingress Path Verification**
   - Confirm packets arrive at `gwi-<X>` interface
   - Verify Geneve decapsulation correctness
   - Test with IPv4 and IPv6 traffic

2. **Interface Creation**
   - Verify only `gwi-<X>` interfaces created
   - Confirm no `gwo-<X>` interfaces present
   - Test hook script execution

3. **Return Path Validation**
   - Confirm return traffic uses alternative path
   - Verify no packets sent back to GWLB
   - Test routing configuration

#### Performance Testing

1. **Throughput Benchmarks**
   - Compare packet processing rates vs. two-arm mode
   - Measure CPU utilization reduction
   - Test with varying packet sizes

2. **Memory Profiling**
   - Measure memory footprint reduction
   - Verify no flow cache allocation
   - Test under sustained high traffic

3. **Multi-threading Efficiency**
   - Test with various thread configurations
   - Measure lock contention reduction
   - Verify thread affinity effectiveness

### 12. Documentation References

- **Main README**: `aws-gateway-load-balancer-tunnel-handler/README.md`
- **Source Code**: `utils.h`, `GeneveHandler.h`, `GeneveHandler.cpp`
- **Example Scripts**: `example-scripts/` directory
- **Health Check**: `HealthCheck.h`, `FlowCacheHealthCheck.cpp`

### 13. Revision History

| Date | Version | Author | Description |
|------|---------|--------|-------------|
| 2025-12-03 | 1.0 | System | Initial documentation for NO_RETURN_TRAFFIC mode enablement |

---

## Summary

Enabling `NO_RETURN_TRAFFIC` mode transforms gwlbtun from a bidirectional tunnel handler into a high-performance, receive-only decapsulation engine. This change eliminates flow tracking overhead and egress interfaces, optimizing for passive monitoring and inspection use cases where return traffic to GWLB is not required.

**Key Takeaway**: This is a one-way traffic mode optimized for monitoring, inspection, and forwarding scenarios where responses do not need to return through the GWLB path.
