import app from './app'
import { config } from './config/env'

app.listen(config.port, () => {
  console.log(`SecureVault backend listening on port ${config.port} [${config.nodeEnv}]`)
})

export default app
