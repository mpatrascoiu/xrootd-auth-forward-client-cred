#include <XrdOuc/XrdOucTrace.hh>
#include <XrdOuc/XrdOucEnv.hh>
#include <XrdOuc/XrdOucStream.hh>
#include <XrdOuc/XrdOucString.hh>
#include <XrdSys/XrdSysError.hh>
#include "AuthForwardClientCred.hh"


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
    mParam(param)    { mSssRegistry = 0; }

AuthForwardClientCred::~AuthForwardClientCred() {}

XrdAccPrivs AuthForwardClientCred::Access(const XrdSecEntity    *entity,
                                   const char            *path,
                                   const Access_Operation oper,
                                   XrdOucEnv             *env)
{
  const char   *theID = 0;
  XrdSecsssID  *sssIdRegistry;
  XrdSecEntity *FwdClientEntity;

  /* Get SSS Registry handle */
  sssIdRegistry = getsssRegistry();

// Register the sec entity into the registry only if we have a valid ID
//
  if (theID = generatePssIDfromTraceIdent(entity->tident)) {
    TkEroute.Say("[AuthForwardClientCred] Registering sec entity: id=", theID,
                 " name=", entity->name);

    FwdClientEntity = copySecEntity(entity, "sss");
    sssIdRegistry->Register(theID, FwdClientEntity, 1);

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

const char *AuthForwardClientCred::generatePssIDfromTraceIdent(const char *tident)
{
  char *id = 0, *idP, idBuff[8];

  if (tident) {
    if (*tident == '=') id = (char *) tident + 1;
    else if (tident = index(tident, ':')) {
      strncpy(idBuff, tident + 1, 7); idBuff[7] = 0;
      if (idP = index(idBuff, '@')) { *idP = 0; id = idBuff; }
    }
  }

  return id ? strdup(id)  : id;
}

XrdSecEntity *AuthForwardClientCred::copySecEntity(const XrdSecEntity *entity,
                                                   const char *pName)
{
  XrdSecEntity *copyEntity = new XrdSecEntity(pName);

  copyEntity->name   = entity->name   ? strdup(entity->name)   : 0;
  copyEntity->grps   = entity->grps   ? strdup(entity->grps)   : 0;
  copyEntity->host   = entity->host   ? strdup(entity->host)   : 0;
  copyEntity->tident = entity->tident ? strdup(entity->tident) : 0;

  return copyEntity;
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
