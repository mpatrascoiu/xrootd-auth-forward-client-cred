#include <XrdOuc/XrdOucTrace.hh>
#include <XrdOuc/XrdOucEnv.hh>
#include <XrdOuc/XrdOucStream.hh>
#include <XrdOuc/XrdOucString.hh>
#include <XrdSys/XrdSysError.hh>
#include "AuthForwardClientCred.hh"
#include "/home/mipatras/workspace/xrootd/src/XrdSecsss/XrdSecsssID.hh"


XrdSysError TkEroute(0, "AuthForwardClientCred");
XrdOucTrace TkTrace(&TkEroute);

XrdVERSIONINFO(XrdAccAuthorizeObject, AuthChangeName);

/*
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger *lp,
                                                     const char   *cfn,
                                                     const char   *parm,
                                                     XrdVersionInfo &vInfo);
*/

AuthForwardClientCred::AuthForwardClientCred(XrdSysLogger *logger,
                               const char   *config,
                               const char   *param)
  : mLogger(logger),
    mConfig(config),
    mParam(param)    {}

AuthForwardClientCred::~AuthForwardClientCred() {}

XrdAccPrivs AuthForwardClientCred::Access(const XrdSecEntity    *entity,
                                   const char            *path,
                                   const Access_Operation oper,
                                   XrdOucEnv             *env)
{
  const char   *theID = 0;
  XrdSecsssID  *sssIdRegistry;

  /* Get SSS Registry handle */
  sssIdRegistry = getsssRegistry();

// Register the sec entity into the registry only if we have a valid ID
//
  if (theID = generatePssIDfromEntity(entity)) {
    TkEroute.Say("[AuthForwardClientCred] Registering sec entity: id=", theID,
                 " name=", entity->name);

    sssIdRegistry->Register(theID, (XrdSecEntity *) &entity, 1);

    /* Enforce SSS security */
    setenv("XrdSecPROTOCOL", "sss", 1);
  }

  return XrdAccPriv_All;
}

XrdSecsssID *AuthForwardClientCred::getsssRegistry()
{
  char *dID;
  int   dIDLen;
  XrdSecsssID::authType aType;

  if (mSssRegistry) return mSssRegistry;

  mSssRegistry = XrdSecsssID::getObj(aType, &dID, dIDLen);
  if (!mSssRegistry) { mSssRegistry = new XrdSecsssID(XrdSecsssID::idDynamic); }
  free(dID);

  return mSssRegistry;
}

const char *AuthForwardClientCred::generatePssIDfromEntity(const XrdSecEntity *entity)
{
  const char *ident = entity->tident;
  char *id = 0, *idP, idBuff[8];

  if (ident) {
    if (*ident == '=') id = (char *) ident + 1;
    else if (ident = index(ident, ':')) {
      strncpy(idBuff, ident + 1, 7); idBuff[7] = 0;
      if (idP = index(idBuff, '@')) { *idP = 0; id = idBuff; }
    }
  }

  return id ? strdup(id)  : id;
}

extern "C" XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                                  const char   *cfn,
                                                  const char   *parm)
{
  TkEroute.SetPrefix("access_auth_forwardclientcred_");
  TkEroute.logger(lp);

  AuthForwardClientCred *authlib = new AuthForwardClientCred(lp, cfn, parm);
  XrdAccAuthorize* acc = dynamic_cast<XrdAccAuthorize*>(authlib);

  if (acc == 0) {
    TkEroute.Say("Failed to create AuthForwardClientCred object!");
  }

  return acc;
}
