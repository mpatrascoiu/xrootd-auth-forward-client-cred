#ifndef __XROOTD_AUTH_FORWARD_CLIENT_CRED_HH__
#define __XROOTD_AUTH_FORWARD_CLIENT_CRED_HH__

#include <XrdAcc/XrdAccAuthorize.hh>
#include <XrdAcc/XrdAccPrivs.hh>
#include <XrdSec/XrdSecEntity.hh>
#include <XrdSys/XrdSysLogger.hh>
#include <XrdVersion.hh>
#include <stdio.h>
#include <sys/types.h>
#include <string>
#include "../../xrootd/src/XrdSecsss/XrdSecsssID.hh"


class AuthForwardClientCred : public XrdAccAuthorize
{

public:
  AuthForwardClientCred(XrdSysLogger *logger, const char *config, const char *param);
  virtual ~AuthForwardClientCred(void);

  XrdAccPrivs Access(const XrdSecEntity    *entity,
                     const char            *path,
                     const Access_Operation oper,
                     XrdOucEnv             *env=0);

  virtual int Audit(const int              accok,
                    const XrdSecEntity    *entity,
                    const char            *path,
                    const Access_Operation oper,
                    XrdOucEnv             *env=0) { return 0; }

  virtual int Test(const XrdAccPrivs      priv,
                   const Access_Operation open) { return 0; };

private:
  // getsssRegistry() attempts to retrieve an existing SSS Registry
  //                  or creates it otherwise
  XrdSecsssID *getsssRegistry();
  // generatePssIDfromEntity() creates the same user ID the PSS component will use.
  //                           The ID is generated from the sec entity tident field.
  const char *generatePssIDfromEntity(const XrdSecEntity *entity);

  XrdSysLogger *mLogger;
  const char *mConfig;
  const char *mParam;

};

#endif  // __XROOTD_AUTH_FORWARD_CLIENT_CRED_HH__
