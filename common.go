package ies

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lvdund/ngap/aper"
)

func encodeMessage(w io.Writer, present uint8, procedureCode int64, criticality aper.Enumerated, ies []F1apMessageIE) (err error) {
	aw := aper.NewWriter(w)
	if err = aw.WriteBool(aper.Zero); err != nil {
		return
	}
	if err = aw.WriteChoice(uint64(present), 2, true); err != nil {
		return
	}
	pCode := ProcedureCode{
		Value: aper.Integer(procedureCode),
	}
	if err = pCode.Encode(aw); err != nil {
		return
	}
	cr := Criticality{
		Value: criticality,
	}
	if err = cr.Encode(aw); err != nil {
		return
	}
	if len(ies) == 0 {
		err = fmt.Errorf("empty message")
		return
	}

	var buf bytes.Buffer
	cW := aper.NewWriter(&buf) // container writer
	cW.WriteBool(aper.Zero)
	if err = aper.WriteSequenceOf[F1apMessageIE](ies, cW, &aper.Constraint{
		Lb: 0,
		Ub: int64(aper.POW_16 - 1),
	}, false); err != nil {
		return
	}

	if err = cW.Close(); err != nil {
		return
	}
	if err = aw.WriteOpenType(buf.Bytes()); err != nil {
		return
	}
	err = aw.Close()
	return
}

// represent an IE in F1ap messages
type F1apMessageIE struct {
	Id          ProtocolIEID // protocol IE identity
	Criticality Criticality
	Value       aper.AperMarshaller // open type
}

func (ie F1apMessageIE) Encode(w *aper.AperWriter) (err error) {
	//1. encode protocol Ie Id
	if err = ie.Id.Encode(w); err != nil {
		return
	}
	//2. encode criticality
	if err = ie.Criticality.Encode(w); err != nil {
		return
	}
	//3. encode F1apIE
	//encode IE into a byte array first
	var buf bytes.Buffer
	ieW := aper.NewWriter(&buf)
	if err = ie.Value.Encode(ieW); err != nil {
		return
	}
	ieW.Close()
	//then write the array as open type
	err = w.WriteOpenType(buf.Bytes())
	return
}

type ProcedureCode struct {
	Value aper.Integer `aper:"valueLB:0,valueUB:255"`
}

func (ie *ProcedureCode) Decode(r *aper.AperReader) error {
	if v, err := r.ReadInteger(&aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return err
	} else {
		ie.Value = aper.Integer(v)
	}
	return nil
}
func (ie *ProcedureCode) Encode(r *aper.AperWriter) (err error) {
	if err = r.WriteInteger(int64(ie.Value), &aper.Constraint{Lb: 0, Ub: 255}, false); err != nil {
		return err
	}
	return nil
}

type TriggeringMessage struct {
	Value aper.Enumerated `aper:"valueLB:0,valueUB:2"`
}

func (ie *TriggeringMessage) Decode(r *aper.AperReader) error {
	if v, err := r.ReadInteger(&aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return err
	} else {
		ie.Value = aper.Enumerated(v)
	}
	return nil
}
func (ie *TriggeringMessage) Encode(r *aper.AperWriter) (err error) {
	if err = r.WriteEnumerate(uint64(ie.Value), aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return err
	}
	return nil
}

type Criticality struct {
	Value aper.Enumerated `aper:"valueLB:0,valueUB:2"`
}

func (ie *Criticality) Decode(r *aper.AperReader) error {
	if v, err := r.ReadInteger(&aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return err
	} else {
		ie.Value = aper.Enumerated(v)
	}
	return nil
}
func (ie *Criticality) Encode(r *aper.AperWriter) (err error) {
	if err = r.WriteEnumerate(uint64(ie.Value), aper.Constraint{Lb: 0, Ub: 2}, false); err != nil {
		return err
	}
	return nil
}

type ProtocolIEID struct {
	Value aper.Integer `aper:"valueLB:0,valueUB:65535"`
}

func (ie *ProtocolIEID) Decode(r *aper.AperReader) error {
	if v, err := r.ReadInteger(&aper.Constraint{Lb: 0, Ub: 65535}, false); err != nil {
		return err
	} else {
		ie.Value = aper.Integer(v)
	}
	return nil
}
func (ie *ProtocolIEID) Encode(r *aper.AperWriter) (err error) {
	if err = r.WriteInteger(int64(ie.Value), &aper.Constraint{Lb: 0, Ub: 65535}, false); err != nil {
		return err
	}
	return nil
}

// type TransactionID struct {
// 	Value aper.Integer `aper:"valueLB:0,valueUB:255"`
// }

func BuildDiagnostics(present uint8, procedureCode ProcedureCode, criticality Criticality, diagnosticsItems []CriticalityDiagnosticsIEItem) *CriticalityDiagnostics {
	return &CriticalityDiagnostics{
		ProcedureCode:             &procedureCode,
		TriggeringMessage:         &TriggeringMessage{Value: aper.Enumerated(present)},
		ProcedureCriticality:      &criticality,
		TransactionID:             TransactionID,
		IEsCriticalityDiagnostics: diagnosticsItems,
	}
}

func msgErrors(err1, err2 error) error {
	if err1 == nil && err2 == nil {
		return nil
	}
	if err1 == nil {
		return err2
	}
	if err2 == nil {
		return err1
	}
	return fmt.Errorf("%v: %v", err1, err2)
}

const (
	F1apPresentNothing uint8 = iota
	F1apPduInitiatingMessage
	F1apPduSuccessfulOutcome
	F1apPduUnsuccessfulOutcome
)

const (
	ProcedureCode_Reset                                    = 0
	ProcedureCode_F1Setup                                  = 1
	ProcedureCode_ErrorIndication                          = 2
	ProcedureCode_gNBDUConfigurationUpdate                 = 3
	ProcedureCode_gNBCUConfigurationUpdate                 = 4
	ProcedureCode_UEContextSetup                           = 5
	ProcedureCode_UEContextRelease                         = 6
	ProcedureCode_UEContextModification                    = 7
	ProcedureCode_UEContextModificationRequired            = 8
	ProcedureCode_UEMobilityCommand                        = 9
	ProcedureCode_UEContextReleaseRequest                  = 10
	ProcedureCode_InitialULRRCMessageTransfer              = 11
	ProcedureCode_DLRRCMessageTransfer                     = 12
	ProcedureCode_ULRRCMessageTransfer                     = 13
	ProcedureCode_PrivateMessage                           = 14
	ProcedureCode_UEInactivityNotification                 = 15
	ProcedureCode_gNBDUResourceCoordination                = 16
	ProcedureCode_SystemInformationDeliveryCommand         = 17
	ProcedureCode_Paging                                   = 18
	ProcedureCode_Notify                                   = 19
	ProcedureCode_WriteReplaceWarning                      = 20
	ProcedureCode_PWSCancel                                = 21
	ProcedureCode_PWSRestartIndication                     = 22
	ProcedureCode_PWSFailureIndication                     = 23
	ProcedureCode_gNBDUStatusIndication                    = 24
	ProcedureCode_RRCDeliveryReport                        = 25
	ProcedureCode_F1Removal                                = 26
	ProcedureCode_NetworkAccessRateReduction               = 27
	ProcedureCode_TraceStart                               = 28
	ProcedureCode_DeactivateTrace                          = 29
	ProcedureCode_DUCURadioInformationTransfer             = 30
	ProcedureCode_CUDURadioInformationTransfer             = 31
	ProcedureCode_BAPMappingConfiguration                  = 32
	ProcedureCode_gNBDUResourceConfiguration               = 33
	ProcedureCode_IABTNLAddressAllocation                  = 34
	ProcedureCode_IABUPConfigurationUpdate                 = 35
	ProcedureCode_ResourceStatusReportingInitiation        = 36
	ProcedureCode_ResourceStatusReporting                  = 37
	ProcedureCode_AccessAndMobilityIndication              = 38
	ProcedureCode_AccessSuccess                            = 39
	ProcedureCode_CellTrafficTrace                         = 40
	ProcedureCode_PositioningMeasurementExchange           = 41
	ProcedureCode_PositioningAssistanceInformationControl  = 42
	ProcedureCode_PositioningAssistanceInformationFeedback = 43
	ProcedureCode_PositioningMeasurementReport             = 44
	ProcedureCode_PositioningMeasurementAbort              = 45
	ProcedureCode_PositioningMeasurementFailureIndication  = 46
	ProcedureCode_PositioningMeasurementUpdate             = 47
	ProcedureCode_TRPInformationExchange                   = 48
	ProcedureCode_PositioningInformationExchange           = 49
	ProcedureCode_PositioningActivation                    = 50
	ProcedureCode_PositioningDeactivation                  = 51
	ProcedureCode_ECIDMeasurementInitiation                = 52
	ProcedureCode_ECIDMeasurementFailureIndication         = 53
	ProcedureCode_ECIDMeasurementReport                    = 54
	ProcedureCode_ECIDMeasurementTermination               = 55
	ProcedureCode_PositioningInformationUpdate             = 56
	ProcedureCode_ReferenceTimeInformationReport           = 57
	ProcedureCode_ReferenceTimeInformationReportingControl = 58
)

const (
	Criticality_PresentReject aper.Enumerated = 0
	Criticality_PresentIgnore aper.Enumerated = 1
	Criticality_PresentNotify aper.Enumerated = 2
)

const (
	ProtocolIEID_Cause                                          = 0
	ProtocolIEID_CellsFailedToBeActivatedList                   = 1
	ProtocolIEID_CellsFailedToBeActivatedListItem               = 2
	ProtocolIEID_CellsToBeActivatedList                         = 3
	ProtocolIEID_CellsToBeActivatedListItem                     = 4
	ProtocolIEID_CellsToBeDeactivatedList                       = 5
	ProtocolIEID_CellsToBeDeactivatedListItem                   = 6
	ProtocolIEID_CriticalityDiagnostics                         = 7
	ProtocolIEID_CUtoDURRCInformation                           = 9
	ProtocolIEID_DRBsFailedToBeModifiedItem                     = 12
	ProtocolIEID_DRBsFailedToBeModifiedList                     = 13
	ProtocolIEID_DRBsFailedToBeSetupItem                        = 14
	ProtocolIEID_DRBsFailedToBeSetupList                        = 15
	ProtocolIEID_DRBsFailedToBeSetupModItem                     = 16
	ProtocolIEID_DRBsFailedToBeSetupModList                     = 17
	ProtocolIEID_DRBsModifiedConfItem                           = 18
	ProtocolIEID_DRBsModifiedConfList                           = 19
	ProtocolIEID_DRBsModifiedItem                               = 20
	ProtocolIEID_DRBsModifiedList                               = 21
	ProtocolIEID_DRBsRequiredToBeModifiedItem                   = 22
	ProtocolIEID_DRBsRequiredToBeModifiedList                   = 23
	ProtocolIEID_DRBsRequiredToBeReleasedItem                   = 24
	ProtocolIEID_DRBsRequiredToBeReleasedList                   = 25
	ProtocolIEID_DRBsSetupItem                                  = 26
	ProtocolIEID_DRBsSetupList                                  = 27
	ProtocolIEID_DRBsSetupModItem                               = 28
	ProtocolIEID_DRBsSetupModList                               = 29
	ProtocolIEID_DRBsToBeModifiedItem                           = 30
	ProtocolIEID_DRBsToBeModifiedList                           = 31
	ProtocolIEID_DRBsToBeReleasedItem                           = 32
	ProtocolIEID_DRBsToBeReleasedList                           = 33
	ProtocolIEID_DRBsToBeSetupItem                              = 34
	ProtocolIEID_DRBsToBeSetupList                              = 35
	ProtocolIEID_DRBsToBeSetupModItem                           = 36
	ProtocolIEID_DRBsToBeSetupModList                           = 37
	ProtocolIEID_DRXCycle                                       = 38
	ProtocolIEID_DUtoCURRCInformation                           = 39
	ProtocolIEID_gNBCUUEF1APID                                  = 40
	ProtocolIEID_gNBDUUEF1APID                                  = 41
	ProtocolIEID_gNBDUID                                        = 42
	ProtocolIEID_gNBDUServedCellsItem                           = 43
	ProtocolIEID_gNBDUServedCellsList                           = 44
	ProtocolIEID_gNBDUName                                      = 45
	ProtocolIEID_NRCellID                                       = 46
	ProtocolIEID_oldgNBDUUEF1APID                               = 47
	ProtocolIEID_ResetType                                      = 48
	ProtocolIEID_ResourceCoordinationTransferContainer          = 49
	ProtocolIEID_RRCContainer                                   = 50
	ProtocolIEID_SCellToBeRemovedItem                           = 51
	ProtocolIEID_SCellToBeRemovedList                           = 52
	ProtocolIEID_SCellToBeSetupItem                             = 53
	ProtocolIEID_SCellToBeSetupList                             = 54
	ProtocolIEID_SCellToBeSetupModItem                          = 55
	ProtocolIEID_SCellToBeSetupModList                          = 56
	ProtocolIEID_ServedCellsToAddItem                           = 57
	ProtocolIEID_ServedCellsToAddList                           = 58
	ProtocolIEID_ServedCellsToDeleteItem                        = 59
	ProtocolIEID_ServedCellsToDeleteList                        = 60
	ProtocolIEID_ServedCellsToModifyItem                        = 61
	ProtocolIEID_ServedCellsToModifyList                        = 62
	ProtocolIEID_SpCellID                                       = 63
	ProtocolIEID_SRBID                                          = 64
	ProtocolIEID_SRBsFailedToBeSetupItem                        = 65
	ProtocolIEID_SRBsFailedToBeSetupList                        = 66
	ProtocolIEID_SRBsFailedToBeSetupModItem                     = 67
	ProtocolIEID_SRBsFailedToBeSetupModList                     = 68
	ProtocolIEID_SRBsRequiredToBeReleasedItem                   = 69
	ProtocolIEID_SRBsRequiredToBeReleasedList                   = 70
	ProtocolIEID_SRBsToBeReleasedItem                           = 71
	ProtocolIEID_SRBsToBeReleasedList                           = 72
	ProtocolIEID_SRBsToBeSetupItem                              = 73
	ProtocolIEID_SRBsToBeSetupList                              = 74
	ProtocolIEID_SRBsToBeSetupModItem                           = 75
	ProtocolIEID_SRBsToBeSetupModList                           = 76
	ProtocolIEID_TimeToWait                                     = 77
	ProtocolIEID_TransactionID                                  = 78
	ProtocolIEID_TransmissionActionIndicator                    = 79
	ProtocolIEID_UEAssociatedLogicalF1ConnectionItem            = 80
	ProtocolIEID_UEAssociatedLogicalF1ConnectionListResAck      = 81
	ProtocolIEID_gNBCUName                                      = 82
	ProtocolIEID_SCellFailedToSetupList                         = 83
	ProtocolIEID_SCellFailedToSetupItem                         = 84
	ProtocolIEID_SCellFailedToSetupModList                      = 85
	ProtocolIEID_SCellFailedToSetupModItem                      = 86
	ProtocolIEID_RRCReconfigurationCompleteIndicator            = 87
	ProtocolIEID_CellsStatusItem                                = 88
	ProtocolIEID_CellsStatusList                                = 89
	ProtocolIEID_CandidateSpCellList                            = 90
	ProtocolIEID_CandidateSpCellItem                            = 91
	ProtocolIEID_PotentialSpCellList                            = 92
	ProtocolIEID_PotentialSpCellItem                            = 93
	ProtocolIEID_FullConfiguration                              = 94
	ProtocolIEID_CRNTI                                          = 95
	ProtocolIEID_SpCellULConfigured                             = 96
	ProtocolIEID_InactivityMonitoringRequest                    = 97
	ProtocolIEID_InactivityMonitoringResponse                   = 98
	ProtocolIEID_DRBActivityItem                                = 99
	ProtocolIEID_DRBActivityList                                = 100
	ProtocolIEID_EUTRANRCellResourceCoordinationReqContainer    = 101
	ProtocolIEID_EUTRANRCellResourceCoordinationReqAckContainer = 102
	ProtocolIEID_ProtectedEUTRAResourcesList                    = 105
	ProtocolIEID_RequestType                                    = 106
	ProtocolIEID_ServCellIndex                                  = 107
	ProtocolIEID_RATFrequencyPriorityInformation                = 108
	ProtocolIEID_ExecuteDuplication                             = 109
	ProtocolIEID_NRCGI                                          = 111
	ProtocolIEID_PagingCellItem                                 = 112
	ProtocolIEID_PagingCellList                                 = 113
	ProtocolIEID_PagingDRX                                      = 114
	ProtocolIEID_PagingPriority                                 = 115
	ProtocolIEID_SITypeList                                     = 116
	ProtocolIEID_UEIdentityIndexValue                           = 117
	ProtocolIEID_gNBCUSystemInformation                         = 118
	ProtocolIEID_HandoverPreparationInformation                 = 119
	ProtocolIEID_GNBCUTNLAssociationToAddItem                   = 120
	ProtocolIEID_GNBCUTNLAssociationToAddList                   = 121
	ProtocolIEID_GNBCUTNLAssociationToRemoveItem                = 122
	ProtocolIEID_GNBCUTNLAssociationToRemoveList                = 123
	ProtocolIEID_GNBCUTNLAssociationToUpdateItem                = 124
	ProtocolIEID_GNBCUTNLAssociationToUpdateList                = 125
	ProtocolIEID_MaskedIMEISV                                   = 126
	ProtocolIEID_PagingIdentity                                 = 127
	ProtocolIEID_DUtoCURRCContainer                             = 128
	ProtocolIEID_CellsToBeBarredList                            = 129
	ProtocolIEID_CellsToBeBarredItem                            = 130
	ProtocolIEID_TAISliceSupportList                            = 131
	ProtocolIEID_GNBCUTNLAssociationSetupList                   = 132
	ProtocolIEID_GNBCUTNLAssociationSetupItem                   = 133
	ProtocolIEID_GNBCUTNLAssociationFailedToSetupList           = 134
	ProtocolIEID_GNBCUTNLAssociationFailedToSetupItem           = 135
	ProtocolIEID_DRBNotifyItem                                  = 136
	ProtocolIEID_DRBNotifyList                                  = 137
	ProtocolIEID_NotificationControl                            = 138
	ProtocolIEID_RANAC                                          = 139
	ProtocolIEID_PWSSystemInformation                           = 140
	ProtocolIEID_RepetitionPeriod                               = 141
	ProtocolIEID_NumberOfBroadcastRequest                       = 142
	ProtocolIEID_CellsToBeBroadcastList                         = 144
	ProtocolIEID_CellsToBeBroadcastItem                         = 145
	ProtocolIEID_CellsBroadcastCompletedList                    = 146
	ProtocolIEID_CellsBroadcastCompletedItem                    = 147
	ProtocolIEID_BroadcastToBeCancelledList                     = 148
	ProtocolIEID_BroadcastToBeCancelledItem                     = 149
	ProtocolIEID_CellsBroadcastCancelledList                    = 150
	ProtocolIEID_CellsBroadcastCancelledItem                    = 151
	ProtocolIEID_NRCGIListForRestartList                        = 152
	ProtocolIEID_NRCGIListForRestartItem                        = 153
	ProtocolIEID_PWSFailedNRCGIList                             = 154
	ProtocolIEID_PWSFailedNRCGIItem                             = 155
	ProtocolIEID_ConfirmedUEID                                  = 156
	ProtocolIEID_CancelAllWarningMessagesIndicator              = 157
	ProtocolIEID_GNBDUUEAMBRUL                                  = 158
	ProtocolIEID_DRXConfigurationIndicator                      = 159
	ProtocolIEID_RLCStatus                                      = 160
	ProtocolIEID_DLPDCPSNLength                                 = 161
	ProtocolIEID_GNBDUConfigurationQuery                        = 162
	ProtocolIEID_MeasurementTimingConfiguration                 = 163
	ProtocolIEID_DRBInformation                                 = 164
	ProtocolIEID_ServingPLMN                                    = 165
	ProtocolIEID_ProtectedEUTRAResourcesItem                    = 168
	ProtocolIEID_GNBCURRCVersion                                = 170
	ProtocolIEID_GNBDURRCVersion                                = 171
	ProtocolIEID_GNBDUOverloadInformation                       = 172
	ProtocolIEID_CellGroupConfig                                = 173
	ProtocolIEID_RLCFailureIndication                           = 174
	ProtocolIEID_UplinkTxDirectCurrentListInformation           = 175
	ProtocolIEID_DCBasedDuplicationConfigured                   = 176
	ProtocolIEID_DCBasedDuplicationActivation                   = 177
	ProtocolIEID_SULAccessIndication                            = 178
	ProtocolIEID_AvailablePLMNList                              = 179
	ProtocolIEID_PDUSessionID                                   = 180
	ProtocolIEID_ULPDUSessionAggregateMaximumBitRate            = 181
	ProtocolIEID_ServingCellMO                                  = 182
	ProtocolIEID_QoSFlowMappingIndication                       = 183
	ProtocolIEID_RRCDeliveryStatusRequest                       = 184
	ProtocolIEID_RRCDeliveryStatus                              = 185
	ProtocolIEID_BearerTypeChange                               = 186
	ProtocolIEID_RLCMode                                        = 187
	ProtocolIEID_DuplicationActivation                          = 188
	ProtocolIEID_DedicatedSIDeliveryNeededUEList                = 189
	ProtocolIEID_DedicatedSIDeliveryNeededUEItem                = 190
	ProtocolIEID_DRXLongCycleStartOffset                        = 191
	ProtocolIEID_ULPDCPSNLength                                 = 192
	ProtocolIEID_SelectedBandCombinationIndex                   = 193
	ProtocolIEID_SelectedFeatureSetEntryIndex                   = 194
	ProtocolIEID_ResourceCoordinationTransferInformation        = 195
	ProtocolIEID_ExtendedServedPLMNsList                        = 196
	ProtocolIEID_ExtendedAvailablePLMNList                      = 197
	ProtocolIEID_AssociatedSCellList                            = 198
	ProtocolIEID_LatestRRCVersionEnhanced                       = 199
	ProtocolIEID_AssociatedSCellItem                            = 200
	ProtocolIEID_CellDirection                                  = 201
	ProtocolIEID_SRBsSetupList                                  = 202
	ProtocolIEID_SRBsSetupItem                                  = 203
	ProtocolIEID_SRBsSetupModList                               = 204
	ProtocolIEID_SRBsSetupModItem                               = 205
	ProtocolIEID_SRBsModifiedList                               = 206
	ProtocolIEID_SRBsModifiedItem                               = 207
	ProtocolIEID_PhInfoSCG                                      = 208
	ProtocolIEID_RequestedBandCombinationIndex                  = 209
	ProtocolIEID_RequestedFeatureSetEntryIndex                  = 210
	ProtocolIEID_RequestedPMaxFR2                               = 211
	ProtocolIEID_DRXConfig                                      = 212
	ProtocolIEID_IgnoreResourceCoordinationContainer            = 213
	ProtocolIEID_UEAssistanceInformation                        = 214
	ProtocolIEID_NeedForGap                                     = 215
	ProtocolIEID_PagingOrigin                                   = 216
	ProtocolIEID_NewGNBCUUEF1APID                               = 217
	ProtocolIEID_RedirectedRRCMessage                           = 218
	ProtocolIEID_NewGNBDUUEF1APID                               = 219
	ProtocolIEID_NotificationInformation                        = 220
	ProtocolIEID_PLMNAssistanceInfoForNetShar                   = 221
	ProtocolIEID_UEContextNotRetrievable                        = 222
	ProtocolIEID_BPLMNIDInfoList                                = 223
	ProtocolIEID_SelectedPLMNID                                 = 224
	ProtocolIEID_UACAssistanceInfo                              = 225
	ProtocolIEID_RANUEID                                        = 226
	ProtocolIEID_GNBDUTNLAssociationToRemoveItem                = 227
	ProtocolIEID_GNBDUTNLAssociationToRemoveList                = 228
	ProtocolIEID_TNLAssociationTransportLayerAddressgNBDU       = 229
	ProtocolIEID_PortNumber                                     = 230
	ProtocolIEID_AdditionalSIBMessageList                       = 231
	ProtocolIEID_CellType                                       = 232
	ProtocolIEID_IgnorePRACHConfiguration                       = 233
	ProtocolIEID_CGConfig                                       = 234
	ProtocolIEID_PDCCHBlindDetectionSCG                         = 235
	ProtocolIEID_RequestedPDCCHBlindDetectionSCG                = 236
	ProtocolIEID_PhInfoMCG                                      = 237
	ProtocolIEID_MeasGapSharingConfig                           = 238
	ProtocolIEID_SystemInformationAreaID                        = 239
	ProtocolIEID_AreaScope                                      = 240
	ProtocolIEID_RRCContainerRRCSetupComplete                   = 241
	ProtocolIEID_TraceActivation                                = 242
	ProtocolIEID_TraceID                                        = 243
	ProtocolIEID_NeighbourCellInformationList                   = 244
	ProtocolIEID_SymbolAllocInSlot                              = 246
	ProtocolIEID_NumDLULSymbols                                 = 247
	ProtocolIEID_AdditionalRRMPriorityIndex                     = 248
	ProtocolIEID_DUCURadioInformationType                       = 249
	ProtocolIEID_CUDURadioInformationType                       = 250
	ProtocolIEID_AggressorGNBDUSetID                            = 251
	ProtocolIEID_VictimGNBDUSetID                               = 252
	ProtocolIEID_LowerLayerPresenceStatusChange                 = 253
	ProtocolIEID_TransportLayerAddressInfo                      = 254
	ProtocolIEID_NeighbourCellInformationItem                   = 255
	ProtocolIEID_IntendedTDDDLULConfig                          = 256
	ProtocolIEID_QosMonitoringRequest                           = 257
	ProtocolIEID_BHChannelsToBeSetupList                        = 258
	ProtocolIEID_BHChannelsToBeSetupItem                        = 259
	ProtocolIEID_BHChannelsSetupList                            = 260
	ProtocolIEID_BHChannelsSetupItem                            = 261
	ProtocolIEID_BHChannelsToBeModifiedItem                     = 262
	ProtocolIEID_BHChannelsToBeModifiedList                     = 263
	ProtocolIEID_BHChannelsToBeReleasedItem                     = 264
	ProtocolIEID_BHChannelsToBeReleasedList                     = 265
	ProtocolIEID_BHChannelsToBeSetupModItem                     = 266
	ProtocolIEID_BHChannelsToBeSetupModList                     = 267
	ProtocolIEID_BHChannelsFailedToBeModifiedItem               = 268
	ProtocolIEID_BHChannelsFailedToBeModifiedList               = 269
	ProtocolIEID_BHChannelsFailedToBeSetupModItem               = 270
	ProtocolIEID_BHChannelsFailedToBeSetupModList               = 271
	ProtocolIEID_BHChannelsModifiedItem                         = 272
	ProtocolIEID_BHChannelsModifiedList                         = 273
	ProtocolIEID_BHChannelsSetupModItem                         = 274
	ProtocolIEID_BHChannelsSetupModList                         = 275
	ProtocolIEID_BHChannelsRequiredToBeReleasedItem             = 276
	ProtocolIEID_BHChannelsRequiredToBeReleasedList             = 277
	ProtocolIEID_BHChannelsFailedToBeSetupItem                  = 278
	ProtocolIEID_BHChannelsFailedToBeSetupList                  = 279
	ProtocolIEID_BHInfo                                         = 280
	ProtocolIEID_BAPAddress                                     = 281
	ProtocolIEID_ConfiguredBAPAddress                           = 282
	ProtocolIEID_BHRoutingInformationAddedList                  = 283
	ProtocolIEID_BHRoutingInformationAddedListItem              = 284
	ProtocolIEID_BHRoutingInformationRemovedList                = 285
	ProtocolIEID_BHRoutingInformationRemovedListItem            = 286
	ProtocolIEID_ULBHNonUPTrafficMapping                        = 287
	ProtocolIEID_ActivatedCellsToBeUpdatedList                  = 288
	ProtocolIEID_ChildNodesList                                 = 289
	ProtocolIEID_IABInfoIABDU                                   = 290
	ProtocolIEID_IABInfoIABDonorCU                              = 291
	ProtocolIEID_IABTNLAddressesToRemoveList                    = 292
	ProtocolIEID_IABTNLAddressesToRemoveItem                    = 293
	ProtocolIEID_IABAllocatedTNLAddressList                     = 294
	ProtocolIEID_IABAllocatedTNLAddressItem                     = 295
	ProtocolIEID_IABIPv6RequestType                             = 296
	ProtocolIEID_IABv4AddressesRequested                        = 297
	ProtocolIEID_IABBarred                                      = 298
	ProtocolIEID_TrafficMappingInformation                      = 299
	ProtocolIEID_ULUPTNLInformationToUpdateList                 = 300
	ProtocolIEID_ULUPTNLInformationToUpdateListItem             = 301
	ProtocolIEID_ULUPTNLAddressToUpdateList                     = 302
	ProtocolIEID_ULUPTNLAddressToUpdateListItem                 = 303
	ProtocolIEID_DLUPTNLAddressToUpdateList                     = 304
	ProtocolIEID_DLUPTNLAddressToUpdateListItem                 = 305
	ProtocolIEID_NRV2XServicesAuthorized                        = 306
	ProtocolIEID_LTEV2XServicesAuthorized                       = 307
	ProtocolIEID_NRUESidelinkAggregateMaximumBitrate            = 308
	ProtocolIEID_LTEUESidelinkAggregateMaximumBitrate           = 309
	ProtocolIEID_SIB12Message                                   = 310
	ProtocolIEID_SIB13Message                                   = 311
	ProtocolIEID_SIB14Message                                   = 312
	ProtocolIEID_SLDRBsFailedToBeModifiedItem                   = 313
	ProtocolIEID_SLDRBsFailedToBeModifiedList                   = 314
	ProtocolIEID_SLDRBsFailedToBeSetupItem                      = 315
	ProtocolIEID_SLDRBsFailedToBeSetupList                      = 316
	ProtocolIEID_SLDRBsModifiedItem                             = 317
	ProtocolIEID_SLDRBsModifiedList                             = 318
	ProtocolIEID_SLDRBsRequiredToBeModifiedItem                 = 319
	ProtocolIEID_SLDRBsRequiredToBeModifiedList                 = 320
	ProtocolIEID_SLDRBsRequiredToBeReleasedItem                 = 321
	ProtocolIEID_SLDRBsRequiredToBeReleasedList                 = 322
	ProtocolIEID_SLDRBsSetupItem                                = 323
	ProtocolIEID_SLDRBsSetupList                                = 324
	ProtocolIEID_SLDRBsToBeModifiedItem                         = 325
	ProtocolIEID_SLDRBsToBeModifiedList                         = 326
	ProtocolIEID_SLDRBsToBeReleasedItem                         = 327
	ProtocolIEID_SLDRBsToBeReleasedList                         = 328
	ProtocolIEID_SLDRBsToBeSetupItem                            = 329
	ProtocolIEID_SLDRBsToBeSetupList                            = 330
	ProtocolIEID_SLDRBsToBeSetupModItem                         = 331
	ProtocolIEID_SLDRBsToBeSetupModList                         = 332
	ProtocolIEID_SLDRBsSetupModList                             = 333
	ProtocolIEID_SLDRBsFailedToBeSetupModList                   = 334
	ProtocolIEID_SLDRBsSetupModItem                             = 335
	ProtocolIEID_SLDRBsFailedToBeSetupModItem                   = 336
	ProtocolIEID_SLDRBsModifiedConfList                         = 337
	ProtocolIEID_SLDRBsModifiedConfItem                         = 338
	ProtocolIEID_UEAssistanceInformationEUTRA                   = 339
	ProtocolIEID_PC5LinkAMBR                                    = 340
	ProtocolIEID_SLPHYMACRLCConfig                              = 341
	ProtocolIEID_SLConfigDedicatedEUTRA                         = 342
	ProtocolIEID_AlternativeQoSParaSetList                      = 343
	ProtocolIEID_CurrentQoSParaSetIndex                         = 344
	ProtocolIEID_gNBCUMeasurementID                             = 345
	ProtocolIEID_gNBDUMeasurementID                             = 346
	ProtocolIEID_RegistrationRequest                            = 347
	ProtocolIEID_ReportCharacteristics                          = 348
	ProtocolIEID_CellToReportList                               = 349
	ProtocolIEID_CellMeasurementResultList                      = 350
	ProtocolIEID_HardwareLoadIndicator                          = 351
	ProtocolIEID_ReportingPeriodicity                           = 352
	ProtocolIEID_TNLCapacityIndicator                           = 353
	ProtocolIEID_CarrierList                                    = 354
	ProtocolIEID_ULCarrierList                                  = 355
	ProtocolIEID_FrequencyShift7p5khz                           = 356
	ProtocolIEID_SSBPositionsInBurst                            = 357
	ProtocolIEID_NRPRACHConfig                                  = 358
	ProtocolIEID_RACHReportInformationList                      = 359
	ProtocolIEID_RLFReportInformationList                       = 360
	ProtocolIEID_TDDULDLConfigCommonNR                          = 361
	ProtocolIEID_CNPacketDelayBudgetDownlink                    = 362
	ProtocolIEID_ExtendedPacketDelayBudget                      = 363
	ProtocolIEID_TSCTrafficCharacteristics                      = 364
	ProtocolIEID_ReportingRequestType                           = 365
	ProtocolIEID_TimeReferenceInformation                       = 366
	ProtocolIEID_CNPacketDelayBudgetUplink                      = 369
	ProtocolIEID_AdditionalPDCPDuplicationTNLList               = 370
	ProtocolIEID_RLCDuplicationInformation                      = 371
	ProtocolIEID_AdditionalDuplicationIndication                = 372
	ProtocolIEID_ConditionalInterDUMobilityInformation          = 373
	ProtocolIEID_ConditionalIntraDUMobilityInformation          = 374
	ProtocolIEID_TargetCellsToCancel                            = 375
	ProtocolIEID_RequestedTargetCellGlobalID                    = 376
	ProtocolIEID_ManagementBasedMDTPLMNList                     = 377
	ProtocolIEID_TraceCollectionEntityIPAddress                 = 378
	ProtocolIEID_PrivacyIndicator                               = 379
	ProtocolIEID_TraceCollectionEntityURI                       = 380
	ProtocolIEID_MDTConfiguration                               = 381
	ProtocolIEID_ServingNID                                     = 382
	ProtocolIEID_NPNBroadcastInformation                        = 383
	ProtocolIEID_NPNSupportInfo                                 = 384
	ProtocolIEID_NID                                            = 385
	ProtocolIEID_AvailableSNPNIDList                            = 386
	ProtocolIEID_SIB10Message                                   = 387
	ProtocolIEID_DLCarrierList                                  = 389
	ProtocolIEID_ExtendedTAISliceSupportList                    = 390
	ProtocolIEID_RequestedSRSTransmissionCharacteristics        = 391
	ProtocolIEID_PosAssistanceInformation                       = 392
	ProtocolIEID_PosBroadcast                                   = 393
	ProtocolIEID_RoutingID                                      = 394
	ProtocolIEID_PosAssistanceInformationFailureList            = 395
	ProtocolIEID_PosMeasurementQuantities                       = 396
	ProtocolIEID_PosMeasurementResultList                       = 397
	ProtocolIEID_TRPInformationTypeListTRPReq                   = 398
	ProtocolIEID_TRPInformationTypeItem                         = 399
	ProtocolIEID_TRPInformationListTRPResp                      = 400
	ProtocolIEID_TRPInformationItem                             = 401
	ProtocolIEID_LMFMeasurementID                               = 402
	ProtocolIEID_SRSType                                        = 403
	ProtocolIEID_ActivationTime                                 = 404
	ProtocolIEID_AbortTransmission                              = 405
	ProtocolIEID_PositioningBroadcastCells                      = 406
	ProtocolIEID_SRSConfiguration                               = 407
	ProtocolIEID_PosReportCharacteristics                       = 408
	ProtocolIEID_PosMeasurementPeriodicity                      = 409
	ProtocolIEID_TRPList                                        = 410
	ProtocolIEID_RANMeasurementID                               = 411
	ProtocolIEID_LMFUEMeasurementID                             = 412
	ProtocolIEID_RANUEMeasurementID                             = 413
	ProtocolIEID_ECIDMeasurementQuantities                      = 414
	ProtocolIEID_ECIDMeasurementQuantitiesItem                  = 415
	ProtocolIEID_ECIDMeasurementPeriodicity                     = 416
	ProtocolIEID_ECIDMeasurementResult                          = 417
	ProtocolIEID_CellPortionID                                  = 418
	ProtocolIEID_SFNInitialisationTime                          = 419
	ProtocolIEID_SystemFrameNumber                              = 420
	ProtocolIEID_SlotNumber                                     = 421
	ProtocolIEID_TRPMeasurementRequestList                      = 422
	ProtocolIEID_MeasurementBeamInfoRequest                     = 423
	ProtocolIEID_ECIDReportCharacteristics                      = 424
	ProtocolIEID_ConfiguredTACIndication                        = 425
	ProtocolIEID_ExtendedGNBDUName                              = 426
	ProtocolIEID_ExtendedGNBCUName                              = 427
)
