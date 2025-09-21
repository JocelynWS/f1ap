package ies

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lvdund/ngap/aper"
	"github.com/reogac/utils"
)

type F1SetupRequest struct {
	TransactionID             TransactionID              `mandatory,reject`
	GNBDUID                   GNBDUID                    `mandatory,reject`
	GNBDUName                 []byte                     `optional,ignore,valueExt`
	GNBDUServedCellsList      []GNBDUServedCellItem      `optional,ignore`
	GNBDURRCVersion           RRCVersion                 `mandatory,reject`
	TransportLayerAddressInfo *TransportLayerAddressInfo `optional,ignore`
	BAPAddress                *BAPAddress                `optional,ignore`
	ExtendedGNBCUName         *ExtendedGNBCUName         `optional,ignore`
}

func (msg *F1SetupRequest) Encode(w io.Writer) (err error) {
	var ies []F1apMessageIE
	if ies, err = msg.toIes(); err != nil {
		err = msgErrors(fmt.Errorf("F1SetupRequest"), err)
		return
	}
	return encodeMessage(w, F1apPduInitiatingMessage, ProcedureCode_F1Setup, Criticality_PresentReject, ies)
}

func (msg *F1SetupRequest) toIes() (ies []F1apMessageIE, err error) {
	ies = []F1apMessageIE{}
	ies = append(ies, F1apMessageIE{
		Id:          ProtocolIEID{Value: ProtocolIEID_TransactionID},
		Criticality: Criticality{Value: Criticality_PresentReject},
		Value:       &msg.TransactionID,
	})
	ies = append(ies, F1apMessageIE{
		Id:          ProtocolIEID{Value: ProtocolIEID_gNBDUID},
		Criticality: Criticality{Value: Criticality_PresentReject},
		Value:       &msg.GNBDUID,
	})
	if msg.GNBDUName != nil {
		ies = append(ies, F1apMessageIE{
			Id:          ProtocolIEID{Value: ProtocolIEID_gNBDUName},
			Criticality: Criticality{Value: Criticality_PresentIgnore},
			Value: &OCTETSTRING{
				c:     aper.Constraint{Lb: 1, Ub: 150},
				ext:   true,
				Value: msg.GNBDUName,
			}})
	}
	if len(msg.GNBDUServedCellsList) > 0 {
		tmp_GNBDUServedCellsList := Sequence[*GNBDUServedCellItem]{
			c:   aper.Constraint{Lb: 1, Ub: maxCellingNBDU},
			ext: false,
		}
		for _, i := range msg.GNBDUServedCellsList {
			tmp_GNBDUServedCellsList.Value = append(tmp_GNBDUServedCellsList.Value, &i)
		}
		ies = append(ies, F1apMessageIE{
			Id:          ProtocolIEID{Value: ProtocolIEID_gNBDUServedCellsList},
			Criticality: Criticality{Value: Criticality_PresentReject},
			Value:       &tmp_GNBDUServedCellsList,
		})
	} else {
		err = utils.WrapError("GNBDUServedCellsList is nil", err)
		return
	}

	ies = append(ies, F1apMessageIE{
		Id:          ProtocolIEID{Value: ProtocolIEID_GNBDURRCVersion},
		Criticality: Criticality{Value: Criticality_PresentReject},
		Value:       msg.GNBDURRCVersion,
	})

	if msg.TransportLayerAddressInfo != nil {
		ies = append(ies, F1apMessageIE{
			Id:          ProtocolIEID{Value: ProtocolIEID_TransportLayerAddressInfo},
			Criticality: Criticality{Value: Criticality_PresentIgnore},
			Value:       msg.TransportLayerAddressInfo,
		})
	}

	if msg.BAPAddress != nil {
		ies = append(ies, F1apMessageIE{
			Id:          ProtocolIEID{Value: ProtocolIEID_BAPAddress},
			Criticality: Criticality{Value: Criticality_PresentIgnore},
			Value:       msg.BAPAddress,
		})
	}

	if msg.ExtendedGNBCUName != nil {
		ies = append(ies, F1apMessageIE{
			Id:          ProtocolIEID{Value: ProtocolIEID_ExtendedGNBCUName},
			Criticality: Criticality{Value: Criticality_PresentIgnore},
			Value:       msg.ExtendedGNBCUName,
		})
	}
	return
}

func (msg *F1SetupRequest) Decode(wire []byte) (err error, diagList []CriticalityDiagnosticsIEItem) {
	defer func() {
		if err != nil {
			err = msgErrors(fmt.Errorf("F1SetupRequest"), err)
		}
	}()
	r := aper.NewReader(bytes.NewReader(wire))
	r.ReadBool()
	decoder := F1SetupRequestDecoder{
		msg:  msg,
		list: make(map[aper.Integer]*F1apMessageIE),
	}
	if _, err = aper.ReadSequenceOf[F1apMessageIE](decoder.decodeIE, r, &aper.Constraint{Lb: 0, Ub: int64(aper.POW_16 - 1)}, false); err != nil {
		return
	}
	if _, ok := decoder.list[ProtocolIEID_TransactionID]; !ok {
		err = fmt.Errorf("Mandatory field TransactionID is missing")
		decoder.diagList = append(decoder.diagList, CriticalityDiagnosticsIEItem{
			IECriticality: Criticality{Value: Criticality_PresentReject},
			IEID:          ProtocolIEID{Value: ProtocolIEID_TransactionID},
			TypeOfError:   TypeOfError{Value: TypeOfErrorMissing},
		})
		return
	}
	if _, ok := decoder.list[ProtocolIEID_gNBDUID]; !ok {
		err = fmt.Errorf("Mandatory field GNBDUID is missing")
		decoder.diagList = append(decoder.diagList, CriticalityDiagnosticsIEItem{
			IECriticality: Criticality{Value: Criticality_PresentReject},
			IEID:          ProtocolIEID{Value: ProtocolIEID_gNBDUID},
			TypeOfError:   TypeOfError{Value: TypeOfErrorMissing},
		})
		return
	}
	if _, ok := decoder.list[ProtocolIEID_GNBDURRCVersion]; !ok {
		err = fmt.Errorf("Mandatory field GNBDURRCVersion is missing")
		decoder.diagList = append(decoder.diagList, CriticalityDiagnosticsIEItem{
			IECriticality: Criticality{Value: Criticality_PresentReject},
			IEID:          ProtocolIEID{Value: ProtocolIEID_GNBDURRCVersion},
			TypeOfError:   TypeOfError{Value: TypeOfErrorMissing},
		})
		return
	}
	return
}

type F1SetupRequestDecoder struct {
	msg      *F1SetupRequest
	diagList []CriticalityDiagnosticsIEItem
	list     map[aper.Integer]*F1apMessageIE
}

func (decoder *F1SetupRequestDecoder) decodeIE(r *aper.AperReader) (msgIe *F1apMessageIE, err error) {
	var id int64
	var c uint64
	var buf []byte

	if id, err = r.ReadInteger(&aper.Constraint{Lb: 0, Ub: int64(aper.POW_16) - 1}, false); err != nil {
		return
	}
	msgIe = new(F1apMessageIE)
	msgIe.Id.Value = aper.Integer(id)

	if c, err = r.ReadEnumerate(aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return
	}
	msgIe.Criticality.Value = aper.Enumerated(c)

	if buf, err = r.ReadOpenType(); err != nil {
		return
	}

	ieId := msgIe.Id.Value
	if _, ok := decoder.list[ieId]; ok {
		err = fmt.Errorf("Duplicated protocol IEID[%d] found", ieId)
		return
	}
	decoder.list[ieId] = msgIe

	ieR := aper.NewReader(bytes.NewReader(buf))
	msg := decoder.msg

	// decode each IE
	switch msgIe.Id.Value {
	case ProtocolIEID_TransactionID:
		var tmp TransactionID
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read TransactionID", err)
			return
		}
		msg.TransactionID = tmp

	case ProtocolIEID_gNBDUID:
		var tmp GNBDUID
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read GNBDUID", err)
			return
		}
		msg.GNBDUID = tmp

	case ProtocolIEID_gNBDUName:
		tmp := OCTETSTRING{
			c:   aper.Constraint{Lb: 1, Ub: 150},
			ext: true,
		}
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read GNBDUName", err)
			return
		}
		msg.GNBDUName = tmp.Value

	case ProtocolIEID_gNBDUServedCellsList:
		tmp := Sequence[*GNBDUServedCellItem]{
			c:   aper.Constraint{Lb: 1, Ub: maxCellingNBDU},
			ext: false,
		}
		fn := func() *GNBDUServedCellItem { return new(GNBDUServedCellItem) }
		if err = tmp.Decode(ieR, fn); err != nil {
			err = utils.WrapError("Read GNBDUServedCellsList", err)
			return
		}
		msg.GNBDUServedCellsList = []GNBDUServedCellItem{}
		for _, i := range tmp.Value {
			msg.GNBDUServedCellsList = append(msg.GNBDUServedCellsList, *i)
		}

	case ProtocolIEID_GNBDURRCVersion:
		var tmp RRCVersion
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read GNBDURRCVersion", err)
			return
		}
		msg.GNBDURRCVersion = tmp

	case ProtocolIEID_TransportLayerAddressInfo:
		var tmp TransportLayerAddressInfo
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read TransportLayerAddressInfo", err)
			return
		}
		msg.TransportLayerAddressInfo = &tmp

	case ProtocolIEID_BAPAddress:
		var tmp BAPAddress
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read BAPAddress", err)
			return
		}
		msg.BAPAddress = &tmp

	case ProtocolIEID_ExtendedGNBCUName:
		var tmp ExtendedGNBCUName
		if err = tmp.Decode(ieR); err != nil {
			err = utils.WrapError("Read ExtendedGNBCUName", err)
			return
		}
		msg.ExtendedGNBCUName = &tmp

	default:
		switch msgIe.Criticality.Value {
		case Criticality_PresentReject:
			fmt.Errorf("Not comprehended IE ID 0x%04x (criticality: reject)", msgIe.Id.Value)
		case Criticality_PresentIgnore:
			fmt.Errorf("Not comprehended IE ID 0x%04x (criticality: ignore)", msgIe.Id.Value)
		case Criticality_PresentNotify:
			fmt.Errorf("Not comprehended IE ID 0x%04x (criticality: notify)", msgIe.Id.Value)
		}
		if msgIe.Criticality.Value != Criticality_PresentIgnore {
			decoder.diagList = append(decoder.diagList, CriticalityDiagnosticsIEItem{
				IECriticality: msgIe.Criticality,
				IEID:          msgIe.Id,
				TypeOfError:   TypeOfError{Value: TypeOfErrorNotunderstood},
			})
		}
	}

	return
}
