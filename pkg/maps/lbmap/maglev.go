// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	// Both inner maps are not being pinned into BPF fs.
	MaglevInner4MapName = "cilium_lb4_maglev_inner"
	MaglevInner6MapName = "cilium_lb6_maglev_inner"

	// Both outer maps are pinned though given we need to attach
	// inner maps into them.
	MaglevOuter4MapName = "cilium_lb4_maglev"
	MaglevOuter6MapName = "cilium_lb6_maglev"
)

var (
	MaglevOuter4Map     *maglevOuterMap
	MaglevOuter6Map     *maglevOuterMap
	maglevRecreatedIPv4 bool
	maglevRecreatedIPv6 bool
)

// InitMaglevMaps inits the ipv4 and/or ipv6 maglev outer and inner maps.
func InitMaglevMaps(ipv4, ipv6 bool, tableSize uint32) error {
	dummyInnerMap, dummyInnerMapSpec, err := NewMaglevInnerMap("cilium_lb_maglev_dummy", tableSize)
	if err != nil {
		return err
	}
	defer dummyInnerMap.Close()

	// Always try to delete old maps with the wrong M parameter, otherwise
	// we may end up in a case where there are 2 maps (one for IPv4 and
	// one for IPv6), one of which is not used, with 2 different table
	// sizes.
	// This would confuse the MaybeInitMaglevMapsByProbingTableSize()
	// function, which would not be able to figure out the correct table
	// size.
	if maglevRecreatedIPv4, err = deleteMapIfMNotMatch(MaglevOuter4MapName, tableSize); err != nil {
		return err
	}
	if maglevRecreatedIPv6, err = deleteMapIfMNotMatch(MaglevOuter6MapName, tableSize); err != nil {
		return err
	}

	if ipv4 {
		MaglevOuter4Map, err = NewMaglevOuterMap(MaglevOuter4MapName, MaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
	}
	if ipv6 {
		MaglevOuter6Map, err = NewMaglevOuterMap(MaglevOuter6MapName, MaxEntries, tableSize, dummyInnerMapSpec)
		if err != nil {
			return err
		}
	}

	return nil
}

// MaybeInitMaglevMapsByProbingTableSize tries to open all already existing
// maglev BPF maps by probing their table size from the inner map value size.
func MaybeInitMaglevMapsByProbingTableSize() (uint32, error) {
	var detectedTableSize uint32

	map4Found, maglev4TableSize := MaglevOuterMapTableSize(MaglevOuter4MapName)
	map6Found, maglev6TableSize := MaglevOuterMapTableSize(MaglevOuter6MapName)

	switch {
	case !map4Found && !map6Found:
		return 0, nil
	case map4Found && maglev4TableSize == UnknownMaglevTableSize:
		return 0, fmt.Errorf("cannot determine v4 outer maglev map's table size")
	case map6Found && maglev6TableSize == UnknownMaglevTableSize:
		return 0, fmt.Errorf("cannot determine v6 outer maglev map's table size")
	case map4Found && map6Found && maglev4TableSize != maglev6TableSize:
		// Just being extra defensive here. This case should never
		// happen as both maps are created at the same time after
		// deleting eventual old maps with a different M parameter
		return 0, fmt.Errorf("v4 and v6 maps have different table sizes")
	case map4Found:
		detectedTableSize = maglev4TableSize
	case map6Found:
		detectedTableSize = maglev6TableSize
	}

	err := InitMaglevMaps(map4Found, map6Found, detectedTableSize)
	if err != nil {
		return 0, err
	}

	return detectedTableSize, nil
}

// GetOpenMaglevMaps returns a map with all the opened outer maglev eBPF maps.
// These BPF maps are indexed by their name.
func GetOpenMaglevMaps() map[string]*maglevOuterMap {
	maps := map[string]*maglevOuterMap{}
	if MaglevOuter4Map != nil {
		maps[MaglevOuter4MapName] = MaglevOuter4Map
	}
	if MaglevOuter6Map != nil {
		maps[MaglevOuter6MapName] = MaglevOuter6Map
	}

	return maps
}

// deleteMapIfMNotMatch removes the outer maglev maps if it's a legacy map or
// the M param (MaglevTableSize) has changed. This is to avoid the verifier
// error when loading BPF programs which access the maps.
func deleteMapIfMNotMatch(mapName string, tableSize uint32) (bool, error) {
	found, prevTableSize := MaglevOuterMapTableSize(mapName)
	if !found {
		// No existing maglev outer map found.
		// Return true so the caller will create a new one.
		return true, nil
	}

	if prevTableSize == tableSize {
		// An outer map with the correct table size already exists.
		// Return false as there no need to delete and recreate it.
		return false, nil
	}

	// An outer map already exists but it has the wrong table size (or we
	// can't determine it). Delete it.
	oldMap, err := ebpf.LoadPinnedMap(bpf.MapPath(mapName))
	if err != nil {
		return false, err
	}
	oldMap.Unpin()

	return true, nil
}

func updateMaglevTable(ipv6 bool, revNATID uint16, backendIDs []uint16) error {
	outerMap := MaglevOuter4Map
	innerMapName := MaglevInner4MapName
	if ipv6 {
		outerMap = MaglevOuter6Map
		innerMapName = MaglevInner6MapName
	}

	innerMap, _, err := NewMaglevInnerMap(innerMapName, outerMap.TableSize)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	innerKey := &MaglevInnerKey{Zero: 0}
	innerVal := &MaglevInnerVal{BackendIDs: backendIDs}
	if err := innerMap.Update(innerKey, innerVal); err != nil {
		return err
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	outerVal := &MaglevOuterVal{FD: uint32(innerMap.FD())}
	if err := outerMap.Update(outerKey, outerVal); err != nil {
		return err
	}

	return nil
}

func deleteMaglevTable(ipv6 bool, revNATID uint16) error {
	outerMap := MaglevOuter4Map
	if ipv6 {
		outerMap = MaglevOuter6Map
	}

	outerKey := (&MaglevOuterKey{RevNatID: revNATID}).ToNetwork()
	if err := outerMap.Delete(outerKey); err != nil {
		return err
	}

	return nil
}
