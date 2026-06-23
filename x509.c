#include "x509.h"

certificate_t *x509_create_from_asn1(field_value_t *root)
{
	certificate_t *cert=malloc(sizeof(*cert));
	cert->tbsCertificate=malloc(sizeof(tbs_certificate_t));

	field_value_t *tbsCertNode=find_child_value(root,"TBSCertificate"); 
	field_value_t *versionNode=find_child_value(tbsCertNode,"version"); 
	int version=bigint_convert_to_int(versionNode->value.bigint);
	cert->tbsCertificate->version=version;
	return cert;
}
