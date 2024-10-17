/**
 * @file
 * @brief command line tool that uses BACnet ReadPropertyMultiple service
 * message to read object property values from another device on
 * the network and prints the values to the console.
 * @author Steve Karg <skarg@users.sourceforge.net>
 * @date 2008
 * @copyright SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h> /* for time */
#if (__STDC_VERSION__ >= 199901L) && defined (__STDC_ISO_10646__)
#include <locale.h>
#endif
#define PRINT_ENABLED 1
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
/* BACnet Stack API */
#include "bacnet/bactext.h"
#include "bacnet/bacerror.h"
#include "bacnet/iam.h"
#include "bacnet/arf.h"
#include "bacnet/npdu.h"
#include "bacnet/apdu.h"
#include "bacnet/rpm.h"
#include "bacnet/whois.h"
#include "bacnet/version.h"
/* some demo stuff needed */
#include "bacnet/basic/binding/address.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/basic/sys/filename.h"
#include "bacnet/basic/services.h"
#include "bacnet/basic/tsm/tsm.h"
#include "bacnet/datalink/datalink.h"
#include "bacnet/datalink/dlenv.h"
#include "bacport.h"
#include <cjson/cJSON.h>

#if BACNET_SVC_SERVER
#error "App requires server-only features disabled! Set BACNET_SVC_SERVER=0"
#endif


/* buffer used for receive */
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

/* global variables used in this file */
static uint32_t Target_Device_Object_Instance = BACNET_MAX_INSTANCE;
static BACNET_READ_ACCESS_DATA *Read_Access_Data;
/* needed to filter incoming messages */
static uint8_t Request_Invoke_ID = 0;
static BACNET_ADDRESS Target_Address;
/* needed for return value of main application */
static bool Error_Detected = false;

static void MyErrorHandler(BACNET_ADDRESS *src,
    uint8_t invoke_id,
    BACNET_ERROR_CLASS error_class,
    BACNET_ERROR_CODE error_code)
{
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf("BACnet Error: %s: %s\n",
            bactext_error_class_name((int)error_class),
            bactext_error_code_name((int)error_code));
        Error_Detected = true;
    }
}

static void MyAbortHandler(
    BACNET_ADDRESS *src, uint8_t invoke_id, uint8_t abort_reason, bool server)
{
    (void)server;
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf(
            "BACnet Abort: %s\n", bactext_abort_reason_name((int)abort_reason));
        Error_Detected = true;
    }
}

static void MyRejectHandler(
    BACNET_ADDRESS *src, uint8_t invoke_id, uint8_t reject_reason)
{
    /* FIXME: verify src and invoke id */
    if (address_match(&Target_Address, src) &&
        (invoke_id == Request_Invoke_ID)) {
        printf("BACnet Reject: %s\n",
            bactext_reject_reason_name((int)reject_reason));
        Error_Detected = true;
    }
}

static void rpm_ack_obj_to_json(BACNET_READ_ACCESS_DATA *rpm_data, cJSON *obj_arr)
{
    BACNET_PROPERTY_REFERENCE *listOfProperties = NULL;
    BACNET_APPLICATION_DATA_VALUE *value = NULL;

    cJSON *obj = NULL;
    cJSON *object_type = NULL;
    cJSON *object_instance = NULL;

    cJSON *properties = NULL;
    cJSON *property = NULL;
    cJSON *property_values = NULL;
    cJSON *property_value = NULL;
    cJSON *error = NULL;

    BACNET_OBJECT_ID *object_id = NULL;
    cJSON *value_object_id = NULL;

    if (rpm_data) {
        obj = cJSON_CreateObject();
        object_type = cJSON_CreateNumber(rpm_data->object_type);
        object_instance = cJSON_CreateNumber(rpm_data->object_instance);
        properties = cJSON_CreateArray();

        listOfProperties = rpm_data->listOfProperties;
        while (listOfProperties) {
            property = cJSON_CreateObject();

            cJSON_AddNumberToObject(property, "propertyIdentifier", listOfProperties->propertyIdentifier);
            if (listOfProperties->propertyArrayIndex == BACNET_ARRAY_ALL) {
                cJSON_AddNullToObject(property, "propertyArrayIndex");
            } else {
                cJSON_AddNumberToObject(property, "propertyArrayIndex", listOfProperties->propertyArrayIndex);
            }

            value = listOfProperties->value;
            if (value) {
                property_values = cJSON_CreateArray();
                while (value) {
                    property_value = cJSON_CreateObject();
                    cJSON_AddNumberToObject(property_value, "valueType", value->tag);
                    switch (value->tag) {
                        case BACNET_APPLICATION_TAG_NULL:
                            cJSON_AddNullToObject(property_value, "value");
                            break;
                        case BACNET_APPLICATION_TAG_BOOLEAN:
                            cJSON_AddBoolToObject(property_value, "value", value->type.Boolean);
                            break;
                        case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                            cJSON_AddNumberToObject(property_value, "value", value->type.Unsigned_Int);
                            break;
                        case BACNET_APPLICATION_TAG_SIGNED_INT:
                            cJSON_AddNumberToObject(property_value, "value", value->type.Signed_Int);
                            break;
                        case BACNET_APPLICATION_TAG_REAL:
                            cJSON_AddNumberToObject(property_value, "value", value->type.Real);
                            break;
                        case BACNET_APPLICATION_TAG_DOUBLE:
                            cJSON_AddNumberToObject(property_value, "value", value->type.Double);
                            break;
                        case BACNET_APPLICATION_TAG_ENUMERATED:
                            cJSON_AddNumberToObject(property_value, "value", value->type.Enumerated);
                            break;
                        case BACNET_APPLICATION_TAG_OBJECT_ID:
                            object_id = &value->type.Object_Id;
                            value_object_id = cJSON_CreateObject();
                            cJSON_AddNumberToObject(value_object_id, "objectType", object_id->type);
                            cJSON_AddNumberToObject(value_object_id, "objectInstance", object_id->instance);
                            cJSON_AddItemToObject(property_value, "value", value_object_id);
                            break;
                        /* case BACNET_APPLICATION_TAG_OCTET_STRING:
                            BACNET_OCTET_STRING *octet_string = &value->type.Octet_String;
                            if (octet_string) {
                                cJSON_AddStringToObject(property_value, "value", octet_string->value);
                            }
                            break;
                        case BACNET_APPLICATION_TAG_CHARACTER_STRING:
                            BACNET_CHARACTER_STRING *char_string = &value->type.Character_String;
                            if (char_string) {
                                cJSON_AddStringToObject(property_value, "value", char_string->value);
                            }
                            break;
                        case BACNET_APPLICATION_TAG_BIT_STRING:
                            break;
                        case BACNET_APPLICATION_TAG_DATE:
                        case BACNET_APPLICATION_TAG_TIME:
                        case BACNET_APPLICATION_TAG_TIMESTAMP:
                        case BACNET_APPLICATION_TAG_DATETIME:
                        case BACNET_APPLICATION_TAG_DATERANGE:
                            break; */
                        default:
                            cJSON_AddStringToObject(property_value, "value", "unsupported");
                            break;
                    }

                    cJSON_AddItemToArray(property_values, property_value);

                    value = value->next;
                }

                cJSON_AddItemToObject(property, "propertyValues", property_values);
                cJSON_AddNullToObject(property, "error");
            } else {
                cJSON_AddNullToObject(property, "propertyValues");
                error = cJSON_CreateObject();
                cJSON_AddNumberToObject(error, "errorClass", listOfProperties->error.error_class);
                cJSON_AddNumberToObject(error, "errorCode", listOfProperties->error.error_code);
                cJSON_AddItemToObject(property, "error", error);
            }

            cJSON_AddItemToArray(properties, property);

            listOfProperties = listOfProperties->next;
        }

        cJSON_AddItemToObject(obj, "objectType", object_type);
        cJSON_AddItemToObject(obj, "objectInstance", object_instance);
        cJSON_AddItemToObject(obj, "properties", properties);
        cJSON_AddItemToArray(obj_arr, obj);
    }
}

/** Handler for a ReadPropertyMultiple ACK.
 * @ingroup DSRPM
 * For each read property, print out the ACK'd data,
 * and free the request data items from linked property list.
 *
 * @param service_request [in] The contents of the service request.
 * @param service_len [in] The length of the service_request.
 * @param src [in] BACNET_ADDRESS of the source of the message
 * @param service_data [in] The BACNET_CONFIRMED_SERVICE_DATA information
 *                          decoded from the APDU header of this message.
 */
static void My_Read_Property_Multiple_Ack_Handler(uint8_t *service_request,
    uint16_t service_len,
    BACNET_ADDRESS *src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA *service_data)
{
    int len = 0;
    BACNET_READ_ACCESS_DATA *rpm_data;
    BACNET_READ_ACCESS_DATA *old_rpm_data;
    BACNET_PROPERTY_REFERENCE *rpm_property;
    BACNET_PROPERTY_REFERENCE *old_rpm_property;
    BACNET_APPLICATION_DATA_VALUE *value;
    BACNET_APPLICATION_DATA_VALUE *old_value;

    uint32_t device_id;
    bool device_id_found = false;
    cJSON *obj;
    cJSON *obj_arr;
    char *json_str = NULL;

    if (address_match(&Target_Address, src) &&
        (service_data->invoke_id == Request_Invoke_ID)) {
        rpm_data = calloc(1, sizeof(BACNET_READ_ACCESS_DATA));
        if (rpm_data) {
            len = rpm_ack_decode_service_request(
                service_request, service_len, rpm_data);
        }

        device_id_found = address_get_device_id(src, &device_id);

        if (len > 0) {
            obj = cJSON_CreateObject();
            obj_arr = cJSON_CreateArray();
            while (rpm_data) {
                rpm_ack_obj_to_json(rpm_data, obj_arr);
                if (device_id_found) {
                    cJSON_AddItemToObject(obj, "deviceInstance", cJSON_CreateNumber(device_id));
                } else {
                    cJSON_AddItemToObject(obj, "deviceInstance", cJSON_CreateNumber(-1));
                }
                cJSON_AddItemToObject(obj, "values", obj_arr);
                /* rpm_ack_print_data(rpm_data); */
                rpm_data = rpm_data_free(rpm_data);
            }
            json_str = cJSON_PrintUnformatted(obj);
            if (json_str) {
                fprintf(stdout, "%s", json_str);
                free(json_str);
            }
            cJSON_Delete(obj);
        } else {
            fprintf(stderr, "RPM Ack Malformed! Freeing memory...\n");
            while (rpm_data) {
                rpm_property = rpm_data->listOfProperties;
                while (rpm_property) {
                    value = rpm_property->value;
                    while (value) {
                        old_value = value;
                        value = value->next;
                        free(old_value);
                    }
                    old_rpm_property = rpm_property;
                    rpm_property = rpm_property->next;
                    free(old_rpm_property);
                }
                old_rpm_data = rpm_data;
                rpm_data = rpm_data->next;
                free(old_rpm_data);
            }
        }
    }
}

static void Init_Service_Handlers(void)
{
    Device_Init(NULL);
    /* we need to handle who-is
       to support dynamic device binding to us */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_bind);
    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler(handler_unrecognized_service);
    /* we must implement read property - it's required! */
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_READ_PROPERTY, handler_read_property);
    /* handle the data coming back from confirmed requests */
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_READ_PROP_MULTIPLE,
        My_Read_Property_Multiple_Ack_Handler);
    /* handle any errors coming back */
    apdu_set_error_handler(SERVICE_CONFIRMED_READ_PROPERTY, MyErrorHandler);
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
}

static void cleanup(void)
{
    BACNET_READ_ACCESS_DATA *rpm_object;
    BACNET_READ_ACCESS_DATA *old_rpm_object;
    BACNET_PROPERTY_REFERENCE *rpm_property;
    BACNET_PROPERTY_REFERENCE *old_rpm_property;

    rpm_object = Read_Access_Data;
    old_rpm_object = rpm_object;
    while (rpm_object) {
        rpm_property = rpm_object->listOfProperties;
        while (rpm_property) {
            old_rpm_property = rpm_property;
            rpm_property = rpm_property->next;
            free(old_rpm_property);
        }
        old_rpm_object = rpm_object;
        rpm_object = rpm_object->next;
        free(old_rpm_object);
    }
}

static void target_address_add(
    long dnet, BACNET_MAC_ADDRESS *mac, BACNET_MAC_ADDRESS *adr)
{
    BACNET_ADDRESS dest = { 0 };

    if (adr->len && mac->len) {
        memcpy(&dest.mac[0], &mac->adr[0], mac->len);
        dest.mac_len = mac->len;
        memcpy(&dest.adr[0], &adr->adr[0], adr->len);
        dest.len = adr->len;
        if ((dnet >= 0) && (dnet <= UINT16_MAX)) {
            dest.net = dnet;
        } else {
            dest.net = BACNET_BROADCAST_NETWORK;
        }
    } else if (mac->len) {
        memcpy(&dest.mac[0], &mac->adr[0], mac->len);
        dest.mac_len = mac->len;
        dest.len = 0;
        if ((dnet >= 0) && (dnet <= UINT16_MAX)) {
            dest.net = dnet;
        } else {
            dest.net = 0;
        }
    } else {
        if ((dnet >= 0) && (dnet <= UINT16_MAX)) {
            dest.net = dnet;
        } else {
            dest.net = BACNET_BROADCAST_NETWORK;
        }
        dest.mac_len = 0;
        dest.len = 0;
    }
    address_add(Target_Device_Object_Instance, MAX_APDU, &dest);
}

static void print_usage(char *filename)
{
    printf("Usage: %s device-instance object-type object-instance "
           "property[index][,property[index]] [object-type ...]\n",
        filename);
    printf("       [--dnet][--dadr][--mac]\n");
    printf("       [--version][--help]\n");
}

static void print_help(char *filename)
{
    printf("Read one or more properties from one or more objects\n"
           "in a BACnet device and print the value(s).\n");
    printf("\n");
    printf("--mac A\n"
           "Optional BACnet mac address."
           "Valid ranges are from 00 to FF (hex) for MS/TP or ARCNET,\n"
           "or an IP string with optional port number like 10.1.2.3:47808\n"
           "or an Ethernet MAC in hex like 00:21:70:7e:32:bb\n");
    printf("\n");
    printf("--dnet N\n"
           "Optional BACnet network number N for directed requests.\n"
           "Valid range is from 0 to 65535 where 0 is the local connection\n"
           "and 65535 is network broadcast.\n");
    printf("\n");
    printf("--dadr A\n"
           "Optional BACnet mac address on the destination BACnet network "
           "number.\n"
           "Valid ranges are from 00 to FF (hex) for MS/TP or ARCNET,\n"
           "or an IP string with optional port number like 10.1.2.3:47808\n"
           "or an Ethernet MAC in hex like 00:21:70:7e:32:bb\n");
    printf("\n");
    printf("device-instance:\n"
           "BACnet Device Object Instance number that you are\n"
           "trying to communicate to.  This number will be used\n"
           "to try and bind with the device using Who-Is and\n"
           "I-Am services.  For example, if you were reading\n"
           "Device Object 123, the device-instance would be 123.\n");
    printf("\n");
    printf("object-type:\n"
           "The object type is object that you are reading. It\n"
           "can be defined either as the object-type name string\n"
           "as defined in the BACnet specification, or as the\n"
           "integer value of the enumeration BACNET_OBJECT_TYPE\n"
           "in bacenum.h. For example if you were reading Analog\n"
           "Output 2, the object-type would be analog-output or 1.\n");
    printf("\n");
    printf("object-instance:\n"
           "This is the object instance number of the object that\n"
           "you are reading.  For example, if you were reading\n"
           "Analog Output 2, the object-instance would be 2.\n");
    printf("\n");
    printf("property:\n"
           "The property is an integer value of the enumeration\n"
           "BACNET_PROPERTY_ID in bacenum.h.  It is the property\n"
           "you are reading.  For example, if you were reading the\n"
           "Present Value property, use 85 as the property.\n");
    printf("\n");
    printf("[index]:\n"
           "This optional integer parameter is the index number of \n"
           "an array property.  Individual elements of an array can\n"
           "be read.  If this parameter is missing and the property\n"
           "is an array, the entire array will be read.\n");
    printf("\n");
    printf("Example:\n"
           "If you want read the PRESENT_VALUE property and various\n"
           "array elements of the PRIORITY_ARRAY in Device 123\n"
           "Analog Output object 99, use one of the following commands:\n"
           "%s 123 analog-output 99 85,87[0],87\n"
           "%s 123 1 99 85,87[0],87\n", filename, filename);
    printf("If you want read the PRESENT_VALUE property in objects\n"
           "Analog Input 77 and Analog Input 78 in Device 123\n"
           "use one of the following commands:\n"
           "%s 123 analog-input 77 85 analog-input 78 85\n"
           "%s 123 0 77 85 0 78 85\n", filename, filename);
    printf("If you want read the ALL property in\n"
           "Device object 123, you would use one of the following commands:\n"
           "%s 123 device 123 8\n"
           "%s 123 8 123 8\n", filename, filename);
    printf("If you want read the OPTIONAL property in\n"
           "Device object 123, you would use one of the following commands:\n"
           "%s 123 device 123 80\n"
           "%s 123 8 123 80\n", filename, filename);
    printf("If you want read the REQUIRED property in\n"
           "Device object 123, you would one of use the following commands:\n"
           "%s 123 device 123 105\n"
           "%s 123 8 123 105\n", filename, filename);
}

int main(int argc, char *argv[])
{
    BACNET_ADDRESS src = { 0 }; /* address where message came from */
    uint16_t pdu_len = 0;
    unsigned timeout = 100; /* milliseconds */
    unsigned max_apdu = 0;
    int tag_value_arg = 0;
    time_t elapsed_seconds = 0;
    time_t last_seconds = 0;
    time_t current_seconds = 0;
    time_t timeout_seconds = 0;
    bool found = false;
    uint8_t buffer[MAX_PDU] = { 0 };
    BACNET_READ_ACCESS_DATA *rpm_object = NULL;
    BACNET_PROPERTY_REFERENCE *rpm_property = NULL;
    char *property_token = NULL;
    unsigned property_id = 0;
    unsigned property_array_index = 0;
    int scan_count = 0;
    int argi = 0;
    long dnet = -1;
    unsigned object_type = 0;
    BACNET_MAC_ADDRESS mac = { 0 };
    BACNET_MAC_ADDRESS adr = { 0 };
    bool specific_address = false;
    unsigned int target_args = 0;
    bool status = false;
    char *filename = NULL;

    filename = filename_remove_path(argv[0]);
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "--help") == 0) {
            print_usage(filename);
            print_help(filename);
            return 0;
        }
        if (strcmp(argv[argi], "--version") == 0) {
            printf("%s %s\n", filename, BACNET_VERSION_TEXT);
            printf("Copyright (C) 2014 by Steve Karg and others.\n"
                   "This is free software; see the source for copying "
                   "conditions.\n"
                   "There is NO warranty; not even for MERCHANTABILITY or\n"
                   "FITNESS FOR A PARTICULAR PURPOSE.\n");
            return 0;
        }
        if (strcmp(argv[argi], "--mac") == 0) {
            if (++argi < argc) {
                if (bacnet_address_mac_from_ascii(&mac, argv[argi])) {
                    specific_address = true;
                }
            }
        } else if (strcmp(argv[argi], "--dnet") == 0) {
            if (++argi < argc) {
                dnet = strtol(argv[argi], NULL, 0);
                if ((dnet >= 0) && (dnet <= UINT16_MAX)) {
                    specific_address = true;
                }
            }
        } else if (strcmp(argv[argi], "--dadr") == 0) {
            if (++argi < argc) {
                if (bacnet_address_mac_from_ascii(&adr, argv[argi])) {
                    specific_address = true;
                }
            }
        } else {
            if (target_args == 0) {
                Target_Device_Object_Instance = strtol(argv[argi], NULL, 0);
                if (Target_Device_Object_Instance > BACNET_MAX_INSTANCE) {
                    fprintf(stderr,
                        "device-instance=%u - not greater than %u\n",
                        Target_Device_Object_Instance, BACNET_MAX_INSTANCE);
                    return 1;
                }
                tag_value_arg = 0;
                target_args++;
            } else if (target_args >= 1) {
                if (tag_value_arg == 0) {
                    if (rpm_object) {
                        rpm_object->next =
                            calloc(1, sizeof(BACNET_READ_ACCESS_DATA));
                        rpm_object = rpm_object->next;
                    } else {
                        Read_Access_Data =
                            calloc(1, sizeof(BACNET_READ_ACCESS_DATA));
                        rpm_object = Read_Access_Data;
                        atexit(cleanup);
                    }
                    status =
                        bactext_object_type_strtol(argv[argi], &object_type);
                    if (status == false) {
                        fprintf(stderr, "Error: object-type=%s invalid\n",
                            argv[argi]);
                        return 1;
                    }
                    rpm_object->object_type = object_type;
                    if (rpm_object->object_type >= MAX_BACNET_OBJECT_TYPE) {
                        fprintf(stderr,
                            "object-type=%u - it must be less than %u\n",
                            rpm_object->object_type, MAX_BACNET_OBJECT_TYPE);
                        return 1;
                    }
                    tag_value_arg++;
                } else if (tag_value_arg == 1) {
                    rpm_object->object_instance = strtol(argv[argi], NULL, 0);
                    if (rpm_object->object_instance > BACNET_MAX_INSTANCE) {
                        fprintf(stderr,
                            "object-instance=%u - not greater than %u\n",
                            rpm_object->object_instance,
                            BACNET_MAX_INSTANCE);
                        return 1;
                    }
                    tag_value_arg++;
                } else if (tag_value_arg == 2) {
                    rpm_property = calloc(1, sizeof(BACNET_PROPERTY_REFERENCE));
                    rpm_object->listOfProperties = rpm_property;
                    property_token = strtok(argv[argi], ",");
                    /* add all the properties and optional index to our list */
                    while (rpm_property) {
                        scan_count = sscanf(property_token, "%u[%u]",
                            &property_id, &property_array_index);
                        if (scan_count > 0) {
                            rpm_property->propertyIdentifier = property_id;
                            if (rpm_property->propertyIdentifier >
                                MAX_BACNET_PROPERTY_ID) {
                                fprintf(stderr,
                                    "property=%u - it must be less than %u\n",
                                    rpm_property->propertyIdentifier,
                                    MAX_BACNET_PROPERTY_ID + 1);
                                return 1;
                            }
                        }
                        if (scan_count > 1) {
                            rpm_property->propertyArrayIndex =
                                property_array_index;
                        } else {
                            rpm_property->propertyArrayIndex = BACNET_ARRAY_ALL;
                        }
                        /* is there another property? */
                        property_token = strtok(NULL, ",");
                        if (property_token) {
                            rpm_property->next =
                                calloc(1, sizeof(BACNET_PROPERTY_REFERENCE));
                            rpm_property = rpm_property->next;
                        } else {
                            rpm_property->next = NULL;
                            break;
                        }
                    }
                    /* start over with the next arg set */
                    tag_value_arg = 0;
                }
            }
        }
    }
    if (tag_value_arg != 0) {
        fprintf(stderr, "Error: not enough object property triples.\n");
        return 1;
    }
    /* setup my info */
    Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    address_init();
    if (specific_address) {
        target_address_add(dnet, &mac, &adr);
    }
    Init_Service_Handlers();
    dlenv_init();
#if (__STDC_VERSION__ >= 199901L) && defined (__STDC_ISO_10646__)
    /* Internationalized programs must call setlocale()
     * to initiate a specific language operation.
     * This can be done by calling setlocale() as follows.
     * If your native locale doesn't use UTF-8 encoding
     * you need to replace the empty string with a
     * locale like "en_US.utf8" which is the same as the string
     * used in the enviromental variable "LANG=en_US.UTF-8".
     */
    setlocale(LC_ALL, "");
#endif
    atexit(datalink_cleanup);
    /* configure the timeout values */
    last_seconds = time(NULL);
    timeout_seconds = (apdu_timeout() / 1000) * apdu_retries();
    /* try to bind with the device */
    found = address_bind_request(
        Target_Device_Object_Instance, &max_apdu, &Target_Address);
    if (!found) {
        Send_WhoIs(
            Target_Device_Object_Instance, Target_Device_Object_Instance);
    }
    /* loop forever */
    for (;;) {
        /* increment timer - exit if timed out */
        current_seconds = time(NULL);

        /* at least one second has passed */
        if (current_seconds != last_seconds) {
            tsm_timer_milliseconds(((current_seconds - last_seconds) * 1000));
            datalink_maintenance_timer(current_seconds - last_seconds);
        }
        if (Error_Detected) {
            break;
        }
        /* wait until the device is bound, or timeout and quit */
        if (!found) {
            found = address_bind_request(
                Target_Device_Object_Instance, &max_apdu, &Target_Address);
        }
        if (found) {
            if (Request_Invoke_ID == 0) {
                Request_Invoke_ID = Send_Read_Property_Multiple_Request(
                    &buffer[0], sizeof(buffer), Target_Device_Object_Instance,
                    Read_Access_Data);
                if (Request_Invoke_ID == 0) {
                    fprintf(stderr, "\rError: failed to send request!\n");
                    break;
                }
            } else if (tsm_invoke_id_free(Request_Invoke_ID)) {
                break;
            } else if (tsm_invoke_id_failed(Request_Invoke_ID)) {
                fprintf(stderr, "\rError: TSM Timeout!\n");
                tsm_free_invoke_id(Request_Invoke_ID);
                Error_Detected = true;
                /* try again or abort? */
                break;
            }
        } else {
            /* increment timer - exit if timed out */
            elapsed_seconds += (current_seconds - last_seconds);
            if (elapsed_seconds > timeout_seconds) {
                printf("\rError: APDU Timeout!\n");
                Error_Detected = true;
                break;
            }
        }

        /* returns 0 bytes on timeout */
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, timeout);

        /* process */
        if (pdu_len) {
            npdu_handler(&src, &Rx_Buf[0], pdu_len);
        }

        /* keep track of time for next check */
        last_seconds = current_seconds;
    }

    if (Error_Detected) {
        return 1;
    }
    return 0;
}
